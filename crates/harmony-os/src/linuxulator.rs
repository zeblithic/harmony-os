// SPDX-License-Identifier: GPL-2.0-or-later
//! Linuxulator — Linux syscall-to-9P translation layer for Ring 3.
//!
//! Translates Linux syscall numbers and arguments into 9P FileServer
//! operations via a [`SyscallBackend`] trait. Manages a POSIX-style
//! fd table that maps Linux file descriptors to 9P fids.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::elf_loader::{self, ElfLoader, InterpreterLoader};
use crate::embedded_fs::EmbeddedFs;
use harmony_microkernel::vm::{FrameClassification, PageFlags, VmError};
use harmony_microkernel::{Fid, FileStat, FileType, IpcError, OpenMode, QPath};
use harmony_netstack::tcp::{NetError, TcpHandle, TcpProvider, TcpSocketState};

// ── Linux errno constants ───────────────────────────────────────────

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const ESRCH: i64 = -3;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const ENOMEM: i64 = -12;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const ENOTDIR: i64 = -20;
const EINVAL: i64 = -22;
const ENODEV: i64 = -19;
const ENOTTY: i64 = -25;
const ESPIPE: i64 = -29;
const EROFS: i64 = -30;
const EPIPE: i64 = -32;
const ERANGE: i64 = -34;
const ENOSYS: i64 = -38;
const EOVERFLOW: i64 = -75;
const EAFNOSUPPORT: i64 = -97;
const ENOTSOCK: i64 = -88;
const ECHILD: i64 = -10;
const ENOEXEC: i64 = -8;
const EEXIST: i64 = -17;
const EADDRINUSE: i64 = -98;
const ECONNREFUSED: i64 = -111;
const ECONNRESET: i64 = -104;
const EINPROGRESS: i64 = -115;
const ENFILE: i64 = -23;
const ENOTCONN: i64 = -107;
const EINTR: i64 = -4;

// Clock IDs (shared by clock_gettime and clock_getres)
const CLOCK_REALTIME: i32 = 0;
const CLOCK_MONOTONIC: i32 = 1;

// File descriptor flags
const FD_CLOEXEC: u32 = 1;
const O_CLOEXEC: i32 = 0o2000000;
const O_NONBLOCK: i32 = 0o4000;

// Signal constants
const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const SIGKILL: u32 = 9;
const SIGSTOP: u32 = 19;
const SIG_BLOCK: i32 = 0;
const SIG_UNBLOCK: i32 = 1;
const SIG_SETMASK: i32 = 2;
const SIGCHLD_NUM: u32 = 17;

// Signal action flags
const SA_SIGINFO: u64 = 4;
const SA_RESTORER: u64 = 0x04000000;
const SA_ONSTACK: u64 = 0x08000000;
const SA_NODEFER: u64 = 0x40000000;
const SA_RESETHAND: u64 = 0x80000000;

// Alternate signal stack constants
const SS_ONSTACK: i32 = 1;
const SS_DISABLE: i32 = 2;
const MINSIGSTKSZ: u64 = 2048;

/// Result of a `block_until` blocking operation.
#[derive(PartialEq, Debug)]
enum BlockResult {
    /// The readiness check returned true — caller should retry the operation.
    Ready,
    /// The 30-second watchdog cap expired — caller should return EINTR.
    Interrupted,
}

/// block_until operation types — match WaitReason encoding in sched.rs.
pub const BLOCK_OP_READABLE: u8 = 0;
pub const BLOCK_OP_WRITABLE: u8 = 1;
pub const BLOCK_OP_CONNECT: u8 = 2;
pub const BLOCK_OP_POLL: u8 = 3;

fn ipc_err_to_errno(e: IpcError) -> i64 {
    match e {
        IpcError::NotFound => ENOENT,
        IpcError::PermissionDenied => -13,   // EACCES
        IpcError::NotOpen => -9,             // EBADF
        IpcError::InvalidFid => -9,          // EBADF
        IpcError::NotDirectory => -20,       // ENOTDIR
        IpcError::IsDirectory => -21,        // EISDIR
        IpcError::ReadOnly => -30,           // EROFS
        IpcError::ResourceExhausted => -12,  // ENOMEM
        IpcError::Conflict => -17,           // EEXIST
        IpcError::NotSupported => -38,       // ENOSYS
        IpcError::InvalidArgument => -22,    // EINVAL
        IpcError::NonceLimitExceeded => -11, // EAGAIN
        IpcError::NotReady => -11,           // EAGAIN — hot-swap in progress, retry
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
        VmError::Overflow(_) => EINVAL,
    }
}

fn net_error_to_errno(e: NetError) -> i64 {
    match e {
        NetError::WouldBlock => EAGAIN,
        NetError::ConnectionRefused => ECONNREFUSED,
        NetError::ConnectionReset => ECONNRESET,
        NetError::NotConnected => ENOTCONN,
        NetError::AddrInUse => EADDRINUSE,
        NetError::InvalidHandle => EBADF,
        NetError::SocketLimit => ENFILE,
    }
}

// ── NoTcp — no-op TcpProvider for non-networked Linuxulators ────

/// No-op [`TcpProvider`] used when TCP is not available.
///
/// All operations return errors; `tcp_fork()` returns `Some(NoTcp)` so
/// that `fork(2)` still works in the default `Linuxulator<B>` config.
pub struct NoTcp;

impl TcpProvider for NoTcp {
    fn tcp_create(&mut self) -> Result<TcpHandle, NetError> {
        Err(NetError::SocketLimit)
    }
    fn tcp_bind(&mut self, _: TcpHandle, _: u16) -> Result<(), NetError> {
        Err(NetError::InvalidHandle)
    }
    fn tcp_listen(&mut self, _: TcpHandle, _: usize) -> Result<(), NetError> {
        Err(NetError::InvalidHandle)
    }
    fn tcp_accept(&mut self, _: TcpHandle) -> Result<Option<TcpHandle>, NetError> {
        Err(NetError::InvalidHandle)
    }
    fn tcp_connect(
        &mut self,
        _: TcpHandle,
        _: harmony_netstack::smoltcp::wire::Ipv4Address,
        _: u16,
    ) -> Result<(), NetError> {
        Err(NetError::InvalidHandle)
    }
    fn tcp_send(&mut self, _: TcpHandle, _: &[u8]) -> Result<usize, NetError> {
        Err(NetError::InvalidHandle)
    }
    fn tcp_recv(&mut self, _: TcpHandle, _: &mut [u8]) -> Result<usize, NetError> {
        Err(NetError::InvalidHandle)
    }
    fn tcp_close(&mut self, _: TcpHandle) -> Result<(), NetError> {
        Err(NetError::InvalidHandle)
    }
    fn tcp_state(&self, _: TcpHandle) -> TcpSocketState {
        TcpSocketState::Closed
    }
    fn tcp_can_recv(&self, _: TcpHandle) -> bool {
        false
    }
    fn tcp_can_send(&self, _: TcpHandle) -> bool {
        false
    }
    fn tcp_set_keepalive(&mut self, _: TcpHandle, _: Option<u64>) {}
    fn tcp_poll(&mut self, _: i64) {}
    fn tcp_fork(&self) -> Option<NoTcp> {
        Some(NoTcp)
    }
}

impl harmony_netstack::udp::UdpProvider for NoTcp {
    fn udp_create(&mut self) -> Result<harmony_netstack::UdpHandle, harmony_netstack::NetError> {
        Err(harmony_netstack::NetError::SocketLimit)
    }
    fn udp_bind(
        &mut self,
        _: harmony_netstack::UdpHandle,
        _: u16,
    ) -> Result<(), harmony_netstack::NetError> {
        Err(harmony_netstack::NetError::InvalidHandle)
    }
    fn udp_close(
        &mut self,
        _: harmony_netstack::UdpHandle,
    ) -> Result<(), harmony_netstack::NetError> {
        Err(harmony_netstack::NetError::InvalidHandle)
    }
    fn udp_can_recv(&self, _: harmony_netstack::UdpHandle) -> bool {
        false
    }
    fn udp_can_send(&self, _: harmony_netstack::UdpHandle) -> bool {
        false
    }
    fn udp_sendto(
        &mut self,
        _: harmony_netstack::UdpHandle,
        _: &[u8],
        _: harmony_netstack::smoltcp::wire::Ipv4Address,
        _: u16,
    ) -> Result<usize, harmony_netstack::NetError> {
        Err(harmony_netstack::NetError::InvalidHandle)
    }
    fn udp_recvfrom(
        &mut self,
        _: harmony_netstack::UdpHandle,
        _: &mut [u8],
    ) -> Result<
        (usize, harmony_netstack::smoltcp::wire::Ipv4Address, u16),
        harmony_netstack::NetError,
    > {
        Err(harmony_netstack::NetError::InvalidHandle)
    }
    fn udp_connect(
        &mut self,
        _: harmony_netstack::UdpHandle,
        _: harmony_netstack::smoltcp::wire::Ipv4Address,
        _: u16,
    ) -> Result<(), harmony_netstack::NetError> {
        Err(harmony_netstack::NetError::InvalidHandle)
    }
    fn udp_send(
        &mut self,
        _: harmony_netstack::UdpHandle,
        _: &[u8],
    ) -> Result<usize, harmony_netstack::NetError> {
        Err(harmony_netstack::NetError::InvalidHandle)
    }
    fn udp_recv(
        &mut self,
        _: harmony_netstack::UdpHandle,
        _: &mut [u8],
    ) -> Result<
        (usize, harmony_netstack::smoltcp::wire::Ipv4Address, u16),
        harmony_netstack::NetError,
    > {
        Err(harmony_netstack::NetError::InvalidHandle)
    }
    fn udp_poll(&mut self, _: i64) {}
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
    RtSigaction {
        signum: i32,
        act: u64,
        oldact: u64,
        sigsetsize: u64,
    },
    RtSigprocmask {
        how: i32,
        set: u64,
        oldset: u64,
        sigsetsize: u64,
    },
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
    Select {
        nfds: i32,
        readfds: u64,
        writefds: u64,
        exceptfds: u64,
        timeout: u64,
    },
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
    Getpid,
    Getppid,
    Gettid,
    Setsid,
    /// Stub uid/gid syscalls — always succeed in a unikernel.
    SetuidStub,
    /// fsync/fdatasync — no-op (no persistent storage in unikernel).
    FsyncStub,
    Getuid,
    Geteuid,
    Getgid,
    Getegid,
    Madvise {
        addr: u64,
        len: u64,
        advice: i32,
    },
    Futex {
        uaddr: u64,
        op: i32,
        val: u32,
    },
    SchedGetaffinity {
        pid: i32,
        cpusetsize: u64,
        mask: u64,
    },
    Uname {
        buf: u64,
    },
    ClockGettime {
        clockid: i32,
        tp: u64,
    },
    ClockGetres {
        clockid: i32,
        tp: u64,
    },
    Fcntl {
        fd: i32,
        cmd: i32,
        arg: u64,
    },
    Dup {
        oldfd: i32,
    },
    Dup2 {
        oldfd: i32,
        newfd: i32,
    },
    Dup3 {
        oldfd: i32,
        newfd: i32,
        flags: i32,
    },
    Pipe2 {
        fds: u64,
        flags: u64,
    },
    Pipe {
        fds: u64,
    },
    EventFd2 {
        initval: u64,
        flags: u64,
    },
    Socket {
        domain: i32,
        sock_type: i32,
        protocol: i32,
    },
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
    Wait4 {
        pid: i32,
        wstatus: u64,
        options: i32,
        rusage: u64,
    },
    Execve {
        path: u64,
        argv: u64,
        envp: u64,
    },
    Kill {
        pid: i32,
        sig: i32,
    },
    Tgkill {
        tgid: i32,
        tid: i32,
        sig: i32,
    },
    Nanosleep {
        req: u64,
        rem: u64,
    },
    ClockNanosleep {
        clockid: i32,
        flags: i32,
        req: u64,
        rem: u64,
    },
    Prctl {
        option: i32,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    },
    SignalFd {
        fd: i32,
        mask_ptr: u64,
        sizemask: u64,
    },
    SignalFd4 {
        fd: i32,
        mask_ptr: u64,
        sizemask: u64,
        flags: i32,
    },
    TimerfdCreate {
        clockid: i32,
        flags: i32,
    },
    TimerfdSettime {
        fd: i32,
        flags: i32,
        new_value: u64,
        old_value: u64,
    },
    TimerfdGettime {
        fd: i32,
        curr_value: u64,
    },
    Poll {
        fds: u64,
        nfds: u64,
        timeout: i32,
    },
    Ppoll {
        fds: u64,
        nfds: u64,
        tmo_ptr: u64,
        sigmask: u64,
        sigsetsize: u64,
    },
    Readv {
        fd: i32,
        iov: u64,
        iovcnt: i32,
    },
    Socketpair {
        domain: i32,
        sock_type: i32,
        protocol: i32,
        sv: u64,
    },
    Getrlimit {
        resource: i32,
        rlim: u64,
    },
    Setrlimit {
        resource: i32,
        rlim: u64,
    },
    Umask {
        mask: u32,
    },
    Ftruncate {
        fd: i32,
        length: u64,
    },
    Renameat {
        olddirfd: i32,
        oldpath: u64,
        newdirfd: i32,
        newpath: u64,
    },
    RtSigreturn {
        rsp: u64,
    },
    Sigaltstack {
        ss: u64,
        old_ss: u64,
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
            // Legacy open(pathname, flags, mode) → openat(AT_FDCWD, ...)
            2 => LinuxSyscall::Openat {
                dirfd: -100, // AT_FDCWD
                pathname: args[0],
                flags: args[1] as i32,
            },
            3 => LinuxSyscall::Close { fd: args[0] as i32 },
            // Legacy stat(pathname, statbuf) → newfstatat(AT_FDCWD, ..., 0)
            4 => LinuxSyscall::Newfstatat {
                dirfd: -100, // AT_FDCWD
                pathname: args[0],
                statbuf: args[1],
                flags: 0,
            },
            5 => LinuxSyscall::Fstat {
                fd: args[0] as i32,
                buf: args[1],
            },
            // Legacy lstat(pathname, statbuf) → newfstatat(AT_FDCWD, ..., AT_SYMLINK_NOFOLLOW)
            6 => LinuxSyscall::Newfstatat {
                dirfd: -100, // AT_FDCWD
                pathname: args[0],
                statbuf: args[1],
                flags: 0x100, // AT_SYMLINK_NOFOLLOW
            },
            7 => LinuxSyscall::Poll {
                fds: args[0],
                nfds: args[1],
                timeout: args[2] as i32,
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
            13 => LinuxSyscall::RtSigaction {
                signum: args[0] as i32,
                act: args[1],
                oldact: args[2],
                sigsetsize: args[3],
            },
            14 => LinuxSyscall::RtSigprocmask {
                how: args[0] as i32,
                set: args[1],
                oldset: args[2],
                sigsetsize: args[3],
            },
            // nr 15 = rt_sigreturn: NOT mapped here. rt_sigreturn takes no
            // register arguments — the kernel reads RSP from saved pt_regs.
            // The caller must construct LinuxSyscall::RtSigreturn { rsp }
            // directly with the actual RSP value.
            16 => LinuxSyscall::Ioctl {
                fd: args[0] as i32,
                request: args[1],
            },
            19 => LinuxSyscall::Readv {
                fd: args[0] as i32,
                iov: args[1],
                iovcnt: args[2] as i32,
            },
            20 => LinuxSyscall::Writev {
                fd: args[0] as i32,
                iov: args[1],
                iovcnt: args[2] as i32,
            },
            // Legacy access(pathname, mode) → faccessat(AT_FDCWD, ...)
            21 => LinuxSyscall::Faccessat {
                dirfd: -100, // AT_FDCWD
                pathname: args[0],
                mode: args[1] as i32,
            },
            22 => LinuxSyscall::Pipe { fds: args[0] },
            23 => LinuxSyscall::Select {
                nfds: args[0] as i32,
                readfds: args[1],
                writefds: args[2],
                exceptfds: args[3],
                timeout: args[4],
            },
            28 => LinuxSyscall::Madvise {
                addr: args[0],
                len: args[1],
                advice: args[2] as i32,
            },
            32 => LinuxSyscall::Dup {
                oldfd: args[0] as i32,
            },
            33 => LinuxSyscall::Dup2 {
                oldfd: args[0] as i32,
                newfd: args[1] as i32,
            },
            35 => LinuxSyscall::Nanosleep {
                req: args[0],
                rem: args[1],
            },
            39 => LinuxSyscall::Getpid,
            41 => LinuxSyscall::Socket {
                domain: args[0] as i32,
                sock_type: args[1] as i32,
                protocol: args[2] as i32,
            },
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
            53 => LinuxSyscall::Socketpair {
                domain: args[0] as i32,
                sock_type: args[1] as i32,
                protocol: args[2] as i32,
                sv: args[3],
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
            288 => LinuxSyscall::Accept4 {
                fd: args[0] as i32,
                addr: args[1],
                addrlen: args[2],
                flags: args[3] as i32,
            },
            60 => LinuxSyscall::Exit {
                code: args[0] as i32,
            },
            62 => LinuxSyscall::Kill {
                pid: args[0] as i32,
                sig: args[1] as i32,
            },
            63 => LinuxSyscall::Uname { buf: args[0] },
            72 => LinuxSyscall::Fcntl {
                fd: args[0] as i32,
                cmd: args[1] as i32,
                arg: args[2],
            },
            77 => LinuxSyscall::Ftruncate {
                fd: args[0] as i32,
                length: args[1],
            },
            79 => LinuxSyscall::Getcwd {
                buf: args[0],
                size: args[1],
            },
            80 => LinuxSyscall::Chdir { pathname: args[0] },
            81 => LinuxSyscall::Fchdir { fd: args[0] as i32 },
            // Legacy rename(oldpath, newpath) → renameat(AT_FDCWD, ..., AT_FDCWD, ...)
            82 => LinuxSyscall::Renameat {
                olddirfd: -100, // AT_FDCWD
                oldpath: args[0],
                newdirfd: -100, // AT_FDCWD
                newpath: args[1],
            },
            // Legacy mkdir(pathname, mode) → mkdirat(AT_FDCWD, ...)
            83 => LinuxSyscall::Mkdirat {
                dirfd: -100, // AT_FDCWD
                pathname: args[0],
                mode: args[1] as u32,
            },
            // Legacy rmdir(pathname) → unlinkat(AT_FDCWD, ..., AT_REMOVEDIR)
            84 => LinuxSyscall::Unlinkat {
                dirfd: -100, // AT_FDCWD
                pathname: args[0],
                flags: 0x200, // AT_REMOVEDIR
            },
            // Legacy unlink(pathname) → unlinkat(AT_FDCWD, ..., 0)
            87 => LinuxSyscall::Unlinkat {
                dirfd: -100, // AT_FDCWD
                pathname: args[0],
                flags: 0,
            },
            89 => LinuxSyscall::Readlink {
                pathname: args[0],
                buf: args[1],
                bufsiz: args[2],
            },
            95 => LinuxSyscall::Umask {
                mask: args[0] as u32,
            },
            97 => LinuxSyscall::Getrlimit {
                resource: args[0] as i32,
                rlim: args[1],
            },
            74 => LinuxSyscall::FsyncStub, // fsync
            75 => LinuxSyscall::FsyncStub, // fdatasync
            102 => LinuxSyscall::Getuid,
            104 => LinuxSyscall::Getgid,
            105 => LinuxSyscall::SetuidStub, // setuid
            106 => LinuxSyscall::SetuidStub, // setgid
            107 => LinuxSyscall::Geteuid,
            108 => LinuxSyscall::Getegid,
            110 => LinuxSyscall::Getppid,
            112 => LinuxSyscall::Setsid,
            113 => LinuxSyscall::SetuidStub, // setreuid
            114 => LinuxSyscall::SetuidStub, // setregid
            116 => LinuxSyscall::SetuidStub, // setgroups
            117 => LinuxSyscall::SetuidStub, // setresuid
            119 => LinuxSyscall::SetuidStub, // setresgid
            131 => LinuxSyscall::Sigaltstack {
                ss: args[0],
                old_ss: args[1],
            },
            157 => LinuxSyscall::Prctl {
                option: args[0] as i32,
                arg2: args[1],
                arg3: args[2],
                arg4: args[3],
                arg5: args[4],
            },
            158 => LinuxSyscall::ArchPrctl {
                code: args[0] as i32,
                addr: args[1],
            },
            160 => LinuxSyscall::Setrlimit {
                resource: args[0] as i32,
                rlim: args[1],
            },
            186 => LinuxSyscall::Gettid,
            202 => LinuxSyscall::Futex {
                uaddr: args[0],
                op: args[1] as i32,
                val: args[2] as u32,
            },
            204 => LinuxSyscall::SchedGetaffinity {
                pid: args[0] as i32,
                cpusetsize: args[1],
                mask: args[2],
            },
            217 => LinuxSyscall::Getdents64 {
                fd: args[0] as i32,
                dirp: args[1],
                count: args[2],
            },
            218 => LinuxSyscall::SetTidAddress,
            228 => LinuxSyscall::ClockGettime {
                clockid: args[0] as i32,
                tp: args[1],
            },
            229 => LinuxSyscall::ClockGetres {
                clockid: args[0] as i32,
                tp: args[1],
            },
            230 => LinuxSyscall::ClockNanosleep {
                clockid: args[0] as i32,
                flags: args[1] as i32,
                req: args[2],
                rem: args[3],
            },
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
            264 => LinuxSyscall::Renameat {
                olddirfd: args[0] as i32,
                oldpath: args[1],
                newdirfd: args[2] as i32,
                newpath: args[3],
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
            271 => LinuxSyscall::Ppoll {
                fds: args[0],
                nfds: args[1],
                tmo_ptr: args[2],
                sigmask: args[3],
                sigsetsize: args[4],
            },
            273 => LinuxSyscall::SetRobustList,
            290 => LinuxSyscall::EventFd2 {
                initval: args[0],
                flags: args[1],
            },
            292 => LinuxSyscall::Dup3 {
                oldfd: args[0] as i32,
                newfd: args[1] as i32,
                flags: args[2] as i32,
            },
            293 => LinuxSyscall::Pipe2 {
                fds: args[0],
                flags: args[1],
            },
            232 => LinuxSyscall::EpollWait {
                epfd: args[0] as i32,
                events: args[1],
                maxevents: args[2] as i32,
                timeout: args[3] as i32,
            },
            233 => LinuxSyscall::EpollCtl {
                epfd: args[0] as i32,
                op: args[1] as i32,
                fd: args[2] as i32,
                event: args[3],
            },
            234 => LinuxSyscall::Tgkill {
                tgid: args[0] as i32,
                tid: args[1] as i32,
                sig: args[2] as i32,
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
            282 => LinuxSyscall::SignalFd {
                fd: args[0] as i32,
                mask_ptr: args[1],
                sizemask: args[2],
            },
            289 => LinuxSyscall::SignalFd4 {
                fd: args[0] as i32,
                mask_ptr: args[1],
                sizemask: args[2],
                flags: args[3] as i32,
            },
            283 => LinuxSyscall::TimerfdCreate {
                clockid: args[0] as i32,
                flags: args[1] as i32,
            },
            286 => LinuxSyscall::TimerfdSettime {
                fd: args[0] as i32,
                flags: args[1] as i32,
                new_value: args[2],
                old_value: args[3],
            },
            287 => LinuxSyscall::TimerfdGettime {
                fd: args[0] as i32,
                curr_value: args[1],
            },
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
            56 => LinuxSyscall::Clone {
                flags: args[0],
                child_stack: args[1],
                parent_tid: args[2],
                child_tid: args[3],
                tls: args[4],
            },
            57 => LinuxSyscall::Fork,
            58 => LinuxSyscall::Vfork,
            59 => LinuxSyscall::Execve {
                path: args[0],
                argv: args[1],
                envp: args[2],
            },
            61 => LinuxSyscall::Wait4 {
                pid: args[0] as i32,
                wstatus: args[1],
                options: args[2] as i32,
                rusage: args[3],
            },
            435 => LinuxSyscall::Clone3 {
                args: args[0],
                size: args[1],
            },
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
            19 => LinuxSyscall::EventFd2 {
                initval: args[0],
                flags: args[1],
            },
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
            23 => LinuxSyscall::Dup {
                oldfd: args[0] as i32,
            },
            24 => LinuxSyscall::Dup3 {
                oldfd: args[0] as i32,
                newfd: args[1] as i32,
                flags: args[2] as i32,
            },
            25 => LinuxSyscall::Fcntl {
                fd: args[0] as i32,
                cmd: args[1] as i32,
                arg: args[2],
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
            38 => LinuxSyscall::Renameat {
                olddirfd: args[0] as i32,
                oldpath: args[1],
                newdirfd: args[2] as i32,
                newpath: args[3],
            },
            46 => LinuxSyscall::Ftruncate {
                fd: args[0] as i32,
                length: args[1],
            },
            48 => LinuxSyscall::Faccessat {
                dirfd: args[0] as i32,
                pathname: args[1],
                mode: args[2] as i32,
            },
            49 => LinuxSyscall::Chdir { pathname: args[0] },
            50 => LinuxSyscall::Fchdir { fd: args[0] as i32 },
            56 => LinuxSyscall::Openat {
                dirfd: args[0] as i32,
                pathname: args[1],
                flags: args[2] as i32,
            },
            57 => LinuxSyscall::Close { fd: args[0] as i32 },
            59 => LinuxSyscall::Pipe2 {
                fds: args[0],
                flags: args[1],
            },
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
            65 => LinuxSyscall::Readv {
                fd: args[0] as i32,
                iov: args[1],
                iovcnt: args[2] as i32,
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
            98 => LinuxSyscall::Futex {
                uaddr: args[0],
                op: args[1] as i32,
                val: args[2] as u32,
            },
            99 => LinuxSyscall::SetRobustList,
            101 => LinuxSyscall::Nanosleep {
                req: args[0],
                rem: args[1],
            },
            113 => LinuxSyscall::ClockGettime {
                clockid: args[0] as i32,
                tp: args[1],
            },
            114 => LinuxSyscall::ClockGetres {
                clockid: args[0] as i32,
                tp: args[1],
            },
            115 => LinuxSyscall::ClockNanosleep {
                clockid: args[0] as i32,
                flags: args[1] as i32,
                req: args[2],
                rem: args[3],
            },
            123 => LinuxSyscall::SchedGetaffinity {
                pid: args[0] as i32,
                cpusetsize: args[1],
                mask: args[2],
            },
            129 => LinuxSyscall::Kill {
                pid: args[0] as i32,
                sig: args[1] as i32,
            },
            131 => LinuxSyscall::Tgkill {
                tgid: args[0] as i32,
                tid: args[1] as i32,
                sig: args[2] as i32,
            },
            132 => LinuxSyscall::Sigaltstack {
                ss: args[0],
                old_ss: args[1],
            },
            134 => LinuxSyscall::RtSigaction {
                signum: args[0] as i32,
                act: args[1],
                oldact: args[2],
                sigsetsize: args[3],
            },
            135 => LinuxSyscall::RtSigprocmask {
                how: args[0] as i32,
                set: args[1],
                oldset: args[2],
                sigsetsize: args[3],
            },
            // nr 139 = rt_sigreturn: NOT mapped here. rt_sigreturn takes no
            // register arguments — the kernel reads SP from saved pt_regs.
            // The caller must construct LinuxSyscall::RtSigreturn { rsp }
            // directly with the actual SP value.
            160 => LinuxSyscall::Uname { buf: args[0] },
            166 => LinuxSyscall::Umask {
                mask: args[0] as u32,
            },
            167 => LinuxSyscall::Prctl {
                option: args[0] as i32,
                arg2: args[1],
                arg3: args[2],
                arg4: args[3],
                arg5: args[4],
            },
            172 => LinuxSyscall::Getpid,
            173 => LinuxSyscall::Getppid,
            174 => LinuxSyscall::Getuid,
            175 => LinuxSyscall::Geteuid,
            176 => LinuxSyscall::Getgid,
            177 => LinuxSyscall::Getegid,
            178 => LinuxSyscall::Gettid,
            198 => LinuxSyscall::Socket {
                domain: args[0] as i32,
                sock_type: args[1] as i32,
                protocol: args[2] as i32,
            },
            199 => LinuxSyscall::Socketpair {
                domain: args[0] as i32,
                sock_type: args[1] as i32,
                protocol: args[2] as i32,
                sv: args[3],
            },
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
            233 => LinuxSyscall::Madvise {
                addr: args[0],
                len: args[1],
                advice: args[2] as i32,
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
            73 => LinuxSyscall::Ppoll {
                fds: args[0],
                nfds: args[1],
                tmo_ptr: args[2],
                sigmask: args[3],
                sigsetsize: args[4],
            },
            74 => LinuxSyscall::SignalFd4 {
                fd: args[0] as i32,
                mask_ptr: args[1],
                sizemask: args[2],
                flags: args[3] as i32,
            },
            85 => LinuxSyscall::TimerfdCreate {
                clockid: args[0] as i32,
                flags: args[1] as i32,
            },
            86 => LinuxSyscall::TimerfdSettime {
                fd: args[0] as i32,
                flags: args[1] as i32,
                new_value: args[2],
                old_value: args[3],
            },
            87 => LinuxSyscall::TimerfdGettime {
                fd: args[0] as i32,
                curr_value: args[1],
            },
            293 => LinuxSyscall::Rseq,
            220 => LinuxSyscall::Clone {
                flags: args[0],
                child_stack: args[1],
                parent_tid: args[2],
                tls: args[3],
                child_tid: args[4],
            },
            221 => LinuxSyscall::Execve {
                path: args[0],
                argv: args[1],
                envp: args[2],
            },
            260 => LinuxSyscall::Wait4 {
                pid: args[0] as i32,
                wstatus: args[1],
                options: args[2] as i32,
                rusage: args[3],
            },
            435 => LinuxSyscall::Clone3 {
                args: args[0],
                size: args[1],
            },
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

    /// Create a forked copy of this backend for a child process.
    /// Returns None if fork is not supported by this backend.
    fn fork_backend(&self) -> Option<Self>
    where
        Self: Sized,
    {
        None
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
    /// Paths that are character devices (for stat to return FileType::CharDev).
    pub chardev_paths: alloc::collections::BTreeSet<alloc::string::String>,
    /// Fids that represent character devices.
    chardev_fids: alloc::collections::BTreeSet<Fid>,
}

#[cfg(test)]
impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl MockBackend {
    pub fn new() -> Self {
        let mut chardev_paths = alloc::collections::BTreeSet::new();
        // init_stdio walks /dev/serial/log — register as chardev so stat
        // reports FileType::CharDev for stdio fids.
        chardev_paths.insert(alloc::string::String::from("/dev/serial/log"));
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
            chardev_paths,
            chardev_fids: alloc::collections::BTreeSet::new(),
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
        if self.chardev_paths.contains(path) {
            self.chardev_fids.insert(new_fid);
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
        } else if self.chardev_fids.contains(&fid) {
            FileType::CharDev
        } else {
            FileType::Regular
        };
        let size = self.file_content.get(&fid).map_or(0, |c| c.len() as u64);
        Ok(FileStat {
            qpath: 0,
            name: alloc::sync::Arc::from("mock"),
            size,
            file_type,
        })
    }

    fn readdir(&mut self, fid: Fid) -> Result<Vec<DirEntry>, IpcError> {
        self.readdir_entries
            .get(&fid)
            .cloned()
            .ok_or(IpcError::NotDirectory)
    }

    fn fork_backend(&self) -> Option<Self> {
        Some(MockBackend::new())
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

    fn fork_backend(&self) -> Option<Self> {
        Some(VmMockBackend::new(self.budget_pages))
    }
}

// ── Memory arena ──────────────────────────────────────────────────

const PAGE_SIZE: usize = harmony_microkernel::vm::PAGE_SIZE as usize;
/// Stack size allocated for new process images (execve).
const EXECVE_STACK_SIZE: usize = 128 * 1024;

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

/// Read a null-terminated array of string pointers from user memory.
/// Returns empty vec if ptr is 0 (null). Returns at most `max_count`
/// entries; any beyond that are silently dropped.
fn read_string_array(ptr: u64, max_count: usize) -> Vec<alloc::string::String> {
    if ptr == 0 {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut addr = ptr as usize;
    for _ in 0..max_count {
        let str_ptr_bytes = unsafe { core::slice::from_raw_parts(addr as *const u8, 8) };
        let str_ptr = u64::from_ne_bytes([
            str_ptr_bytes[0],
            str_ptr_bytes[1],
            str_ptr_bytes[2],
            str_ptr_bytes[3],
            str_ptr_bytes[4],
            str_ptr_bytes[5],
            str_ptr_bytes[6],
            str_ptr_bytes[7],
        ]);
        if str_ptr == 0 {
            break;
        }
        result.push(unsafe { read_c_string(str_ptr as usize) });
        addr += 8;
    }
    result
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
///
/// If `mode_override` is `Some`, it replaces the mode derived from
/// `stat.file_type`. Used by pipe fstat to set `S_IFIFO` without
/// adding a `Fifo` variant to the microkernel's `FileType` enum.
fn write_linux_stat(buf_ptr: usize, stat: &FileStat) {
    write_linux_stat_with_mode(buf_ptr, stat, None);
}

fn write_linux_stat_with_mode(buf_ptr: usize, stat: &FileStat, mode_override: Option<u32>) {
    let mode: u32 = mode_override.unwrap_or(match stat.file_type {
        FileType::Regular => 0o100000 | 0o644,   // S_IFREG | rw-r--r--
        FileType::Directory => 0o040000 | 0o755, // S_IFDIR | rwxr-xr-x
        FileType::CharDev => 0o020000 | 0o666,   // S_IFCHR | rw-rw-rw-
    });

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

/// What kind of object backs a file descriptor.
#[derive(Clone)]
enum FdKind {
    /// A 9P-backed file (regular, directory, char device, etc.).
    File {
        fid: Fid,
        offset: u64,
        path: Option<alloc::string::String>,
        /// Cached file type — avoids IPC stat on every lseek.
        file_type: FileType,
    },
    /// Read end of a pipe.
    PipeRead { pipe_id: usize },
    /// Write end of a pipe.
    PipeWrite { pipe_id: usize },
    /// eventfd descriptor (shared state via eventfd_id indirection).
    EventFd { eventfd_id: usize },
    /// Socket stub (no real networking).
    Socket { socket_id: usize },
    /// Epoll instance (always-ready stub).
    Epoll { epoll_id: usize },
    /// signalfd descriptor for reading pending signals.
    SignalFd { signalfd_id: usize },
    /// timerfd descriptor for timer expiration.
    TimerFd { timerfd_id: usize },
    /// An in-memory file served from the embedded filesystem.
    EmbeddedFile {
        path: alloc::string::String,
        offset: u64,
    },
    /// /dev/null — reads return EOF, writes are discarded.
    DevNull,
    /// /dev/urandom — reads return random bytes.
    DevUrandom,
    /// A writable scratch file in the EmbeddedFs overlay.
    ScratchFile {
        path: alloc::string::String,
        offset: u64,
    },
}

/// Shared state for an eventfd instance.
struct EventFdState {
    counter: u64,
    semaphore: bool,
}

/// Shared state for a socket instance.
#[derive(Clone)]
struct SocketState {
    domain: i32,
    sock_type: i32,
    listening: bool,
    /// Track whether accept4 has already returned a stub fd. Non-blocking
    /// sockets return EAGAIN on subsequent calls to prevent infinite accept
    /// loops in event-driven callers (epoll always reports ready).
    accepted_once: bool,
    /// Handle into the TcpProvider, if the socket was successfully created
    /// via tcp_create. None for stub/AF_UNIX/AF_INET6 sockets.
    tcp_handle: Option<TcpHandle>,
    /// Handle into the UdpProvider, if socket was created as SOCK_DGRAM
    /// via udp_create. None for SOCK_STREAM/AF_UNIX/stub sockets.
    udp_handle: Option<harmony_netstack::UdpHandle>,
    /// Port this socket is bound to (0 = unbound).
    bound_port: u16,
}

/// Shared state for an epoll instance.
#[derive(Clone)]
struct EpollState {
    /// Registered fds: fd → (event mask, user data).
    interests: BTreeMap<i32, (u32, u64)>,
}

/// State for a signalfd instance.
#[derive(Clone)]
struct SignalFdState {
    /// Which signals this fd monitors (bitmask).
    mask: u64,
}

/// State for a timerfd instance.
#[derive(Clone)]
struct TimerFdState {
    clockid: i32,
    /// Absolute expiration time in nanoseconds (0 = disarmed).
    expiration_ns: u64,
    /// Repeat interval in nanoseconds (0 = one-shot).
    interval_ns: u64,
}

/// Register state the caller provides for signal frame construction.
/// Matches the x86_64 GPR set needed for Linux sigcontext.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SavedRegisters {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub eflags: u64,
}

/// Returned by `setup_signal_frame` — tells the caller where to jump
/// and what register values to set for signal handler invocation.
#[derive(Debug, Clone, Copy)]
pub struct SignalHandlerSetup {
    /// Handler function address (set RIP to this).
    pub handler_rip: u64,
    /// Top of signal frame on user stack (set RSP to this).
    pub handler_rsp: u64,
    /// First argument: signal number.
    pub rdi: u64,
    /// Second argument: pointer to siginfo_t on stack (SA_SIGINFO) or 0.
    pub rsi: u64,
    /// Third argument: pointer to ucontext_t on stack (SA_SIGINFO) or 0.
    pub rdx: u64,
}

/// Returned by `pending_signal_return` — restored register state
/// after rt_sigreturn reads the signal frame from the user stack.
#[derive(Debug, Clone, Copy)]
pub struct SignalReturn {
    pub regs: SavedRegisters,
}

/// Per-signal handler disposition, stored in a 64-element array.
#[derive(Clone, Copy)]
struct SignalAction {
    handler: u64,
    mask: u64,
    flags: u64,
    /// sa_restorer (x86_64 only; 0 on other arches). Needed for
    /// signal stack frame construction in the delivery bead.
    restorer: u64,
}

impl Default for SignalAction {
    fn default() -> Self {
        Self {
            handler: SIG_DFL,
            mask: 0,
            flags: 0,
            restorer: 0,
        }
    }
}

/// Default action for a signal when SIG_DFL is the handler.
enum DefaultAction {
    Terminate,
    Ignore,
}

/// Return the default action for a signal number (1-64).
fn default_signal_action(signum: u32) -> DefaultAction {
    match signum {
        17 | 18 | 23 | 28 => DefaultAction::Ignore, // SIGCHLD, SIGCONT, SIGURG, SIGWINCH
        19..=22 => DefaultAction::Ignore, // SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU (stop not supported)
        _ => DefaultAction::Terminate,
    }
}

/// A child process created by fork/clone.
struct ChildProcess<B: SyscallBackend, T: TcpProvider + harmony_netstack::udp::UdpProvider> {
    pid: i32,
    linuxulator: Linuxulator<B, T>,
}

/// Result of a successful execve — new entry point and stack pointer
/// for the caller to jump to.
pub struct ExecveResult {
    pub entry_point: u64,
    pub stack_pointer: u64,
}

/// Per-fd state: the kind of object and descriptor-level flags.
#[derive(Clone)]
struct FdEntry {
    kind: FdKind,
    /// File descriptor flags (e.g. FD_CLOEXEC). Default 0.
    flags: u32,
    /// Whether this fd is in non-blocking mode. Set by O_NONBLOCK/SOCK_NONBLOCK
    /// at creation time, updated by fcntl(F_SETFL). Applies to all fd kinds
    /// (sockets, pipes, eventfds, etc.).
    nonblock: bool,
}

/// Linux syscall-to-9P translation engine.
///
/// Owns a POSIX-style fd table and dispatches Linux syscalls to a
/// [`SyscallBackend`]. Created once per Linux process.
///
/// The `T` type parameter selects the TCP provider. Use the default
/// [`NoTcp`] when networking is not required.
pub struct Linuxulator<
    B: SyscallBackend,
    T: TcpProvider + harmony_netstack::udp::UdpProvider = NoTcp,
> {
    backend: B,
    /// TCP provider for SOCK_STREAM sockets. [`NoTcp`] by default.
    tcp: T,
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
    /// VM-backed brk: base address of the heap (0 = not yet established).
    vm_brk_base: u64,
    /// VM-backed brk: current program break.
    vm_brk_current: u64,
    /// Call counter for getrandom — ensures repeated calls to the same
    /// buffer address produce distinct output.
    getrandom_counter: u64,
    /// Current working directory (absolute path).
    cwd: alloc::string::String,
    /// Monotonic clock counter in nanoseconds. Incremented by 1_000_000
    /// (1 ms) on each `clock_gettime(CLOCK_MONOTONIC)` call.
    monotonic_ns: u64,
    /// Realtime clock counter in nanoseconds. Incremented by 1_000_000
    /// (1 ms) on each `clock_gettime(CLOCK_REALTIME)` call.
    realtime_ns: u64,
    /// Reference counts for 9P fids shared across multiple fd_table entries
    /// (via dup/dup2/dup3). A fid is only clunked when its refcount reaches 0.
    fid_refcount: BTreeMap<Fid, u32>,
    /// Pipe buffers keyed by pipe_id.
    pipes: BTreeMap<usize, Vec<u8>>,
    /// Next pipe_id to allocate.
    next_pipe_id: usize,
    eventfds: BTreeMap<usize, EventFdState>,
    next_eventfd_id: usize,
    /// Socket state keyed by socket_id.
    sockets: BTreeMap<usize, SocketState>,
    /// Next socket_id to allocate.
    next_socket_id: usize,
    /// Epoll state keyed by epoll_id.
    epolls: BTreeMap<usize, EpollState>,
    /// Next epoll_id to allocate.
    next_epoll_id: usize,
    /// This process's PID.
    pid: i32,
    /// Parent's PID (0 for init).
    parent_pid: i32,
    /// Next PID to assign to a child.
    next_child_pid: i32,
    /// Active children (running, not yet exited).
    children: Vec<ChildProcess<B, T>>,
    /// Exited children: (pid, exit_code, killed_by_signal) triples consumed by waitpid/wait4.
    exited_children: Vec<(i32, i32, Option<u32>)>,
    /// Arena size used for this process (inherited by children on fork).
    arena_size: usize,
    /// Set by sys_execve on success — caller should reset RIP/RSP.
    pending_execve: Option<ExecveResult>,
    /// Per-signal handler disposition (signals 1-64, index 0 = signal 1).
    signal_handlers: [SignalAction; 64],
    /// Blocked signal mask (bit N = signal N+1 is blocked).
    signal_mask: u64,
    /// Pending signal bitmask (bit N = signal N+1 is pending).
    pending_signals: u64,
    /// Signal with custom handler pending for caller invocation.
    pending_handler_signal: Option<u32>,
    /// If set, process was killed by this signal (for wstatus encoding).
    killed_by_signal: Option<u32>,
    /// Process name set by prctl(PR_SET_NAME). 16 bytes max (including null).
    process_name: [u8; 16],
    /// signalfd state keyed by signalfd_id.
    signalfds: BTreeMap<usize, SignalFdState>,
    /// Next signalfd_id to allocate.
    next_signalfd_id: usize,
    /// timerfd state keyed by timerfd_id.
    timerfds: BTreeMap<usize, TimerFdState>,
    /// Next timerfd_id to allocate.
    next_timerfd_id: usize,
    /// File creation mask (umask). Default 0o022.
    umask_val: u32,
    /// Alternate signal stack: base address (ss_sp).
    alt_stack_sp: u64,
    /// Alternate signal stack: size (ss_size).
    alt_stack_size: u64,
    /// Alternate signal stack: flags (0 or SS_DISABLE).
    alt_stack_flags: i32,
    /// Whether currently executing on the alternate signal stack.
    on_alt_stack: bool,
    /// Restored register state from rt_sigreturn, consumed by caller.
    pending_signal_return: Option<SignalReturn>,
    /// Optional in-memory filesystem for embedded binaries and config files.
    embedded_fs: Option<EmbeddedFs>,
    /// Network poll callback for blocking operations (select/poll).
    /// Drives VirtIO RX/TX + smoltcp processing and returns current
    /// time in milliseconds. Set by the kernel at init.
    poll_fn: Option<fn() -> u64>,
    /// Callback to block the current task. Called by block_until() instead
    /// of spin-waiting. Arguments: (op: u8, fd: i32) where op is:
    /// 0=FdReadable, 1=FdWritable, 2=FdConnectDone, 3=PollWait.
    block_fn: Option<fn(u8, i32)>,
    /// Callback to wake a task blocked on a specific fd. Called after
    /// pipe/eventfd writes for synchronous waking. Arguments: (fd: i32, op: u8)
    /// where op is 0=readable, 1=writable.
    wake_fn: Option<fn(i32, u8)>,
}

impl<B: SyscallBackend> Linuxulator<B, NoTcp> {
    /// Create a new Linuxulator with default 1 MiB arena and no TCP support.
    pub fn new(backend: B) -> Self {
        Self::with_tcp_and_arena(backend, NoTcp, 1024 * 1024)
    }

    /// Create a new Linuxulator with a custom arena size and no TCP support.
    pub fn with_arena(backend: B, arena_size: usize) -> Self {
        Self::with_tcp_and_arena(backend, NoTcp, arena_size)
    }
}

impl<B: SyscallBackend, T: TcpProvider + harmony_netstack::udp::UdpProvider> Linuxulator<B, T> {
    /// Create a Linuxulator with a custom TCP provider and default 1 MiB arena.
    pub fn with_tcp(backend: B, tcp: T) -> Self {
        Self::with_tcp_and_arena(backend, tcp, 1024 * 1024)
    }

    /// Create a Linuxulator with a custom TCP provider and custom arena size.
    pub fn with_tcp_and_arena(backend: B, tcp: T, arena_size: usize) -> Self {
        Self {
            backend,
            tcp,
            fd_table: BTreeMap::new(),
            next_fid: 100, // avoid collision with server root fids
            exit_code: None,
            arena: MemoryArena::new(arena_size),
            fs_base: 0,
            vm_brk_base: 0,
            vm_brk_current: 0,
            getrandom_counter: 0,
            cwd: alloc::string::String::from("/"),
            monotonic_ns: 0,
            realtime_ns: 0,
            fid_refcount: BTreeMap::new(),
            pipes: BTreeMap::new(),
            next_pipe_id: 0,
            eventfds: BTreeMap::new(),
            next_eventfd_id: 0,
            sockets: BTreeMap::new(),
            next_socket_id: 0,
            epolls: BTreeMap::new(),
            next_epoll_id: 0,
            pid: 1,
            parent_pid: 0,
            next_child_pid: 2,
            children: Vec::new(),
            exited_children: Vec::new(),
            arena_size,
            pending_execve: None,
            signal_handlers: [SignalAction::default(); 64],
            signal_mask: 0,
            pending_signals: 0,
            pending_handler_signal: None,
            killed_by_signal: None,
            process_name: [0u8; 16],
            signalfds: BTreeMap::new(),
            next_signalfd_id: 0,
            timerfds: BTreeMap::new(),
            next_timerfd_id: 0,
            umask_val: 0o022,
            alt_stack_sp: 0,
            alt_stack_size: 0,
            alt_stack_flags: SS_DISABLE,
            on_alt_stack: false,
            pending_signal_return: None,
            embedded_fs: None,
            poll_fn: None,
            block_fn: None,
            wake_fn: None,
        }
    }

    /// Register an embedded filesystem for serving files without 9P.
    ///
    /// File-related syscalls (`openat`, `read`, `stat`, `execve`, `faccessat`)
    /// check this overlay first and fall through to the 9P backend only when
    /// the requested path is not found here.
    pub fn set_embedded_fs(&mut self, fs: EmbeddedFs) {
        self.embedded_fs = Some(fs);
    }

    /// Set the network poll callback. Called during blocking select/poll
    /// to drive the network stack and read the PIT timer.
    pub fn set_poll_fn(&mut self, f: fn() -> u64) {
        self.poll_fn = Some(f);
    }

    /// Set the blocking callback. Called by block_until() to yield the CPU
    /// to the scheduler instead of spin-waiting.
    pub fn set_block_fn(&mut self, f: fn(u8, i32)) {
        self.block_fn = Some(f);
    }

    /// Set the wake callback. Called after pipe/eventfd writes to immediately
    /// wake any task blocked on the corresponding read end.
    pub fn set_wake_fn(&mut self, f: fn(i32, u8)) {
        self.wake_fn = Some(f);
    }

    /// Drive the network stack. Called by the system task's event loop
    /// to move packets through smoltcp. Wraps the internal poll_fn.
    /// Returns `true` if the network stack was polled (poll_fn is set),
    /// used by the caller to gate PollWait wakeups.
    pub fn poll_network(&mut self) -> bool {
        if let Some(pf) = self.poll_fn {
            pf();
            true
        } else {
            false
        }
    }

    /// Block the current task until woken by the system task's wake-check loop.
    ///
    /// If `block_fn` is set (scheduler available), calls it to yield the CPU.
    /// The task is marked Blocked, a Self-SGI triggers a context switch, and
    /// execution resumes here when woken. Returns `Ready`.
    ///
    /// If `block_fn` is not set (no scheduler), returns `Interrupted` so the
    /// caller can fall back to EAGAIN.
    fn block_until(&mut self, op: u8, fd: i32) -> BlockResult {
        if let Some(block) = self.block_fn {
            block(op, fd);
            // Execution resumes here after wake + reschedule.
            BlockResult::Ready
        } else {
            BlockResult::Interrupted
        }
    }

    /// Find the fd number for the write end of the pipe with the given pipe_id.
    fn find_pipe_write_fd(&self, pipe_id: usize) -> Option<i32> {
        self.fd_table.iter().find_map(|(&fd, entry)| {
            if matches!(entry.kind, FdKind::PipeWrite { pipe_id: id } if id == pipe_id) {
                Some(fd)
            } else {
                None
            }
        })
    }

    /// Find the fd number for the read end of the pipe with the given pipe_id.
    fn find_pipe_read_fd(&self, pipe_id: usize) -> Option<i32> {
        self.fd_table.iter().find_map(|(&fd, entry)| {
            if matches!(entry.kind, FdKind::PipeRead { pipe_id: id } if id == pipe_id) {
                Some(fd)
            } else {
                None
            }
        })
    }

    /// Blocking pipe write retry loop.  Yields to the scheduler until enough
    /// buffer space is available for the write (respecting POSIX atomic
    /// semantics for writes <= PIPE_BUF), then performs the write and returns
    /// the byte count.  Returns EINTR on interrupt, EPIPE on broken pipe,
    /// EAGAIN when no scheduler is available.
    fn pipe_write_blocking(
        &mut self,
        fd: i32,
        pipe_id: usize,
        buf_ptr: usize,
        count: usize,
    ) -> i64 {
        const PIPE_BUF_CAP: usize = 65536;
        const PIPE_BUF: usize = 4096;

        loop {
            // Check if enough space is available.
            let has_reader = self
                .fd_table
                .values()
                .any(|e| matches!(&e.kind, FdKind::PipeRead { pipe_id: id } if *id == pipe_id));
            if !has_reader {
                let is_child = self.parent_pid != 0;
                if !is_child || !self.pipes.contains_key(&pipe_id) {
                    return EPIPE;
                }
            }
            let pipe_buf = match self.pipes.get_mut(&pipe_id) {
                Some(b) => b,
                None => return EPIPE,
            };
            let avail = PIPE_BUF_CAP.saturating_sub(pipe_buf.len());
            if avail > 0 && (count > PIPE_BUF || avail >= count) {
                // Enough space — perform the write.
                let to_write = count.min(avail);
                let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, to_write) };
                pipe_buf.extend_from_slice(data);
                // Wake any task blocked on reading from this pipe.
                if let Some(wake) = self.wake_fn {
                    if let Some(read_fd) = self.find_pipe_read_fd(pipe_id) {
                        wake(read_fd, BLOCK_OP_READABLE);
                    }
                }
                return to_write as i64;
            }

            // Buffer full — block until space available.
            if self.block_fn.is_some() {
                match self.block_until(BLOCK_OP_WRITABLE, fd) {
                    BlockResult::Ready => continue, // Retry write
                    BlockResult::Interrupted => return EINTR,
                }
            } else {
                return EAGAIN;
            }
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

    /// Insert an fd with proper refcounting (test-only).
    ///
    /// Prefer this over raw `fd_table` access to keep fd_table and
    /// fid_refcount in sync — `release_fid` panics if the refcount
    /// entry is missing.
    #[cfg(test)]
    fn insert_test_fd(&mut self, fd: i32, entry: FdEntry) {
        if let FdKind::File { fid, .. } = &entry.kind {
            *self.fid_refcount.entry(*fid).or_insert(0) += 1;
        }
        self.fd_table.insert(fd, entry);
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
                kind: FdKind::File {
                    fid: stdin_fid,
                    offset: 0,
                    path: None,
                    file_type: FileType::CharDev,
                },
                flags: 0,
                nonblock: false,
            },
        );
        self.fid_refcount.insert(stdin_fid, 1);

        // stdout (fd 1) — write mode
        let stdout_fid = self.alloc_fid();
        self.backend.walk("/dev/serial/log", stdout_fid)?;
        self.backend.open(stdout_fid, OpenMode::Write)?;
        self.fd_table.insert(
            1,
            FdEntry {
                kind: FdKind::File {
                    fid: stdout_fid,
                    offset: 0,
                    path: None,
                    file_type: FileType::CharDev,
                },
                flags: 0,
                nonblock: false,
            },
        );
        self.fid_refcount.insert(stdout_fid, 1);

        // stderr (fd 2) — write mode
        let stderr_fid = self.alloc_fid();
        self.backend.walk("/dev/serial/log", stderr_fid)?;
        self.backend.open(stderr_fid, OpenMode::Write)?;
        self.fd_table.insert(
            2,
            FdEntry {
                kind: FdKind::File {
                    fid: stderr_fid,
                    offset: 0,
                    path: None,
                    file_type: FileType::CharDev,
                },
                flags: 0,
                nonblock: false,
            },
        );
        self.fid_refcount.insert(stderr_fid, 1);

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

    /// Recover shared state (pipes/eventfds) from an exited child.
    fn recover_child_state(&mut self) {
        let should_recover = self
            .children
            .last()
            .is_some_and(|c| c.linuxulator.exit_code.is_some());
        if !should_recover {
            return;
        }
        // Pop the exited child so recover is called exactly once.
        // The exit code is stored in exited_children for future waitpid.
        let child = self.children.pop().unwrap();
        let exit_code = child.linuxulator.exit_code.unwrap_or(0);
        let killed_by = child.linuxulator.killed_by_signal;
        self.exited_children.push((child.pid, exit_code, killed_by));

        // Swap pipes/eventfds back from the (now dropped) child.
        // We need to move them out before the child is dropped, so
        // we must do this inline with a temporary.
        // Actually, child is already moved out of the vec by pop().
        let mut c = child.linuxulator;
        core::mem::swap(&mut self.pipes, &mut c.pipes);
        core::mem::swap(&mut self.eventfds, &mut c.eventfds);
        // Recover shared-state allocators (pipes/eventfds are shared,
        // so their ID counters must not collide after recovery).
        self.next_pipe_id = self.next_pipe_id.max(c.next_pipe_id);
        self.next_eventfd_id = self.next_eventfd_id.max(c.next_eventfd_id);
        // Sockets and epolls are cloned (not shared) — child's objects
        // are dropped with the child, so counter recovery is not needed.
        // next_child_pid must be recovered to keep the global PID space.
        self.next_child_pid = self.next_child_pid.max(c.next_child_pid);
        // Auto-deliver SIGCHLD to parent (Linux does this on child exit).
        self.pending_signals |= 1u64 << (SIGCHLD_NUM - 1);
    }

    /// Return the deepest actively-running Linuxulator in the process tree.
    pub fn active_process(&mut self) -> &mut Linuxulator<B, T> {
        // Determine which path to take using a shared borrow (dropped immediately).
        let last_exited = self
            .children
            .last()
            .map(|c| c.linuxulator.exit_code.is_some());

        match last_exited {
            // Child has exited: recover shared state and return self (the parent).
            Some(true) => {
                self.recover_child_state();
                self
            }
            // Active child: recurse into it.
            Some(false) => self
                .children
                .last_mut()
                .unwrap()
                .linuxulator
                .active_process(),
            // No children: this is the active process.
            None => self,
        }
    }

    /// Check for a newly-forked child that needs its first syscall dispatched.
    pub fn pending_fork_child(&mut self) -> Option<(i32, &mut Linuxulator<B, T>)> {
        if let Some(child) = self.children.last_mut() {
            if child.linuxulator.exit_code.is_none() {
                return Some((child.pid, &mut child.linuxulator));
            }
        }
        None
    }

    /// Consume the pending execve result. If Some, the caller should
    /// reset RIP to entry_point and RSP to stack_pointer.
    pub fn pending_execve(&mut self) -> Option<ExecveResult> {
        self.pending_execve.take()
    }

    /// Consume the pending handler signal.
    pub fn pending_handler_signal(&mut self) -> Option<u32> {
        self.pending_handler_signal.take()
    }

    /// Consume the pending signal return (set by rt_sigreturn).
    /// If Some, the caller should restore registers from the returned state.
    ///
    /// **Important:** After an `RtSigreturn` dispatch, the caller must
    /// drain both `pending_signal_return()` and `pending_handler_signal()`.
    /// `rt_sigreturn` restores the signal mask, and `deliver_pending_signals`
    /// (which runs at the end of every `dispatch_syscall`) may immediately
    /// deliver a previously-blocked signal, setting `pending_handler_signal`.
    pub fn pending_signal_return(&mut self) -> Option<SignalReturn> {
        self.pending_signal_return.take()
    }

    /// Build a Linux-compatible signal frame on the user stack and return
    /// the register values the caller must set before jumping to the handler.
    ///
    /// The frame layout (from handler_rsp upward) is:
    ///   +0:   return address (sa_restorer)           8 bytes
    ///   +8:   ucontext_t                           304 bytes
    ///         ├─ uc_flags/uc_link/uc_stack           40 bytes
    ///         ├─ sigcontext (32 u64 × 8)            256 bytes
    ///         └─ uc_sigmask                            8 bytes
    ///   +312: siginfo_t (si_signo + padding)       128 bytes
    /// Total frame: 440 bytes.
    ///
    /// Signal mask management:
    /// 1. Save current mask into sigcontext.oldmask and uc_sigmask
    /// 2. Apply action's sa_mask
    /// 3. Unless SA_NODEFER, block the signal being handled
    /// 4. SIGKILL/SIGSTOP always remain unblockable
    pub fn setup_signal_frame(&mut self, signum: u32, regs: &SavedRegisters) -> SignalHandlerSetup {
        assert!(
            (1..=64).contains(&signum),
            "signum {signum} out of range [1, 64]"
        );
        let idx = (signum - 1) as usize;
        let action = self.signal_handlers[idx];

        assert!(
            action.flags & SA_RESTORER != 0,
            "SA_RESTORER must be set on x86_64"
        );

        // ── Choose stack base ────────────────────────────────────────
        // Save on_alt_stack BEFORE modification — this is written into the
        // frame's uc_stack so rt_sigreturn can restore the correct state
        // for nested signal handlers.
        let was_on_alt_stack = self.on_alt_stack;
        let stack_top = if action.flags & SA_ONSTACK != 0
            && self.alt_stack_flags != SS_DISABLE
            && !self.on_alt_stack
        {
            self.on_alt_stack = true;
            self.alt_stack_sp + self.alt_stack_size
        } else {
            // Subtract 128-byte red zone (x86_64 ABI) to avoid clobbering
            // leaf-function temporaries stored below RSP.
            regs.rsp - 128
        };

        // ── Compute frame pointer ───────────────────────────────────
        // Frame is 440 bytes: 8 (retaddr) + 304 (ucontext) + 128 (siginfo)
        const FRAME_SIZE: u64 = 8 + 304 + 128;
        let frame_base = stack_top - FRAME_SIZE;
        // Align down to 16 then subtract 8 so handler_rsp ≡ 8 (mod 16),
        // simulating the state after a `call` instruction.
        let handler_rsp = (frame_base & !0xF) - 8;

        // Save the current signal mask before modification.
        let saved_mask = self.signal_mask;

        // ── Write return address (sa_restorer) ──────────────────────
        let retaddr_ptr = handler_rsp;
        unsafe {
            core::ptr::write_unaligned(retaddr_ptr as *mut u64, action.restorer);
        }

        // ── Write ucontext_t (304 bytes) ────────────────────────────
        let ucontext_ptr = handler_rsp + 8;
        // Zero the entire ucontext_t region.
        unsafe {
            core::ptr::write_bytes(ucontext_ptr as *mut u8, 0, 304);
        }

        // ── Write siginfo_t (128 bytes) ─────────────────────────────
        let siginfo_ptr = handler_rsp + 8 + 304; // = handler_rsp + 312
                                                 // Zero the entire siginfo_t region.
        unsafe {
            core::ptr::write_bytes(siginfo_ptr as *mut u8, 0, 128);
        }
        // si_signo at offset 0 of siginfo_t (i32).
        unsafe {
            core::ptr::write_unaligned(siginfo_ptr as *mut i32, signum as i32);
        }

        // ucontext header: uc_flags(u64)=0, uc_link(u64)=0, uc_stack(24 bytes)
        // uc_stack saves the sigaltstack configuration (matching Linux's
        // __save_altstack), with SS_ONSTACK reflecting pre-delivery state.
        let uc_stack_ptr = ucontext_ptr + 16; // after uc_flags + uc_link
        unsafe {
            core::ptr::write_unaligned(uc_stack_ptr as *mut u64, self.alt_stack_sp);
            core::ptr::write_unaligned(
                (uc_stack_ptr + 8) as *mut i32,
                self.alt_stack_flags | if was_on_alt_stack { SS_ONSTACK } else { 0 },
            );
            core::ptr::write_unaligned((uc_stack_ptr + 16) as *mut u64, self.alt_stack_size);
        }

        // sigcontext starts at ucontext + 40 (after header).
        // 32 u64 slots × 8 bytes = 256 bytes.
        // Layout: r8-r15(8), rdi/rsi/rbp/rbx(4), rdx/rax/rcx/rsp(4),
        //         rip/eflags(2), cs_gs_fs_pad(1 packed u64),
        //         err(1), trapno(1), oldmask(1), cr2(1), fpstate(1),
        //         reserved1[8] (zeroed)
        let sc_ptr = ucontext_ptr + 40;
        unsafe {
            // GPR fields at offsets 0..
            core::ptr::write_unaligned(sc_ptr as *mut u64, regs.r8);
            core::ptr::write_unaligned((sc_ptr + 8) as *mut u64, regs.r9);
            core::ptr::write_unaligned((sc_ptr + 16) as *mut u64, regs.r10);
            core::ptr::write_unaligned((sc_ptr + 24) as *mut u64, regs.r11);
            core::ptr::write_unaligned((sc_ptr + 32) as *mut u64, regs.r12);
            core::ptr::write_unaligned((sc_ptr + 40) as *mut u64, regs.r13);
            core::ptr::write_unaligned((sc_ptr + 48) as *mut u64, regs.r14);
            core::ptr::write_unaligned((sc_ptr + 56) as *mut u64, regs.r15);
            core::ptr::write_unaligned((sc_ptr + 64) as *mut u64, regs.rdi);
            core::ptr::write_unaligned((sc_ptr + 72) as *mut u64, regs.rsi);
            core::ptr::write_unaligned((sc_ptr + 80) as *mut u64, regs.rbp);
            core::ptr::write_unaligned((sc_ptr + 88) as *mut u64, regs.rbx);
            core::ptr::write_unaligned((sc_ptr + 96) as *mut u64, regs.rdx);
            core::ptr::write_unaligned((sc_ptr + 104) as *mut u64, regs.rax);
            core::ptr::write_unaligned((sc_ptr + 112) as *mut u64, regs.rcx);
            core::ptr::write_unaligned((sc_ptr + 120) as *mut u64, regs.rsp);
            core::ptr::write_unaligned((sc_ptr + 128) as *mut u64, regs.rip);
            core::ptr::write_unaligned((sc_ptr + 136) as *mut u64, regs.eflags);
            // cs/gs/fs/pad packed u64 at sc+144 — zeroed
            // err at sc+152, trapno at sc+160 — zeroed
            // oldmask at sc+168 (21st field × 8)
            core::ptr::write_unaligned((sc_ptr + 168) as *mut u64, saved_mask);
            // cr2 at sc+176, fpstate at sc+184 — zeroed
        }

        // uc_sigmask at ucontext offset 296 (= ucontext_ptr + 296)
        unsafe {
            core::ptr::write_unaligned((ucontext_ptr + 296) as *mut u64, saved_mask);
        }

        // ── Update signal mask for handler execution ────────────────
        self.signal_mask |= action.mask;
        if action.flags & SA_NODEFER == 0 {
            self.signal_mask |= 1u64 << (signum - 1);
        }
        // SIGKILL and SIGSTOP are never blockable.
        self.signal_mask &= !(1u64 << (SIGKILL - 1));
        self.signal_mask &= !(1u64 << (SIGSTOP - 1));

        // ── SA_RESETHAND: full reset to default disposition ─────────
        if action.flags & SA_RESETHAND != 0 {
            self.signal_handlers[idx].handler = SIG_DFL;
            self.signal_handlers[idx].flags = 0;
            self.signal_handlers[idx].mask = 0;
        }

        // ── Build return value ──────────────────────────────────────
        let (rsi, rdx) = if action.flags & SA_SIGINFO != 0 {
            (siginfo_ptr, ucontext_ptr)
        } else {
            (0, 0)
        };

        SignalHandlerSetup {
            handler_rip: action.handler,
            handler_rsp,
            rdi: signum as u64,
            rsi,
            rdx,
        }
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
        self.fd_table.get(&fd).and_then(|e| match &e.kind {
            FdKind::File { fid, .. } => Some(*fid),
            _ => None,
        })
    }

    /// Base address of the memory arena.
    pub fn arena_base(&self) -> usize {
        self.arena.base
    }

    /// Current end of the brk area (base + brk_offset).
    pub fn arena_brk_end(&self) -> usize {
        self.arena.base + self.arena.brk_offset
    }

    /// Total size of the memory arena in bytes.
    pub fn arena_size(&self) -> usize {
        self.arena_size
    }

    /// Check if an fd is a TCP socket (for watchdog tracking).
    pub fn fd_is_tcp_socket(&self, fd: i32) -> bool {
        self.fd_table
            .get(&fd)
            .map(|e| {
                if let FdKind::Socket { socket_id } = &e.kind {
                    self.sockets
                        .get(socket_id)
                        .map(|s| s.tcp_handle.is_some())
                        .unwrap_or(false)
                } else {
                    false
                }
            })
            .unwrap_or(false)
    }

    /// Return the set of pipe_ids that exist in the pipes map.
    pub fn pipe_ids(&self) -> alloc::vec::Vec<usize> {
        self.pipes.keys().copied().collect()
    }

    /// Return pipe_ids referenced in the fd_table (both read and write ends).
    pub fn fd_pipe_ids(&self) -> alloc::vec::Vec<(i32, usize)> {
        self.fd_table
            .iter()
            .filter_map(|(&fd, e)| match &e.kind {
                FdKind::PipeRead { pipe_id } | FdKind::PipeWrite { pipe_id } => {
                    Some((fd, *pipe_id))
                }
                _ => None,
            })
            .collect()
    }

    /// Snapshot all pipe buffers (clone). Used before arena restore which
    /// might clobber heap-allocated Vec buffers.
    pub fn snapshot_pipes(&self) -> alloc::collections::BTreeMap<usize, alloc::vec::Vec<u8>> {
        self.pipes.clone()
    }

    /// Restore pipe buffers from a snapshot.
    pub fn restore_pipes(
        &mut self,
        snapshot: &alloc::collections::BTreeMap<usize, alloc::vec::Vec<u8>>,
    ) {
        self.pipes = snapshot.clone();
    }

    /// Ensure every pipe_id referenced by the fd_table has an entry in the
    /// pipes map. Inserts an empty buffer for any missing pipe. This is
    /// needed after fork recovery when the child closed pipe fds and the
    /// close handler removed the pipe buffer.
    pub fn heal_pipes(&mut self) {
        let missing: alloc::vec::Vec<usize> = self
            .fd_table
            .values()
            .filter_map(|e| match &e.kind {
                FdKind::PipeRead { pipe_id } | FdKind::PipeWrite { pipe_id }
                    if !self.pipes.contains_key(pipe_id) =>
                {
                    Some(*pipe_id)
                }
                _ => None,
            })
            .collect();
        for pid in missing {
            self.pipes.insert(pid, alloc::vec::Vec::new());
        }
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
        let result = match syscall {
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
            LinuxSyscall::RtSigaction {
                signum,
                act,
                oldact,
                sigsetsize,
            } => self.sys_rt_sigaction(signum, act, oldact, sigsetsize),
            LinuxSyscall::RtSigprocmask {
                how,
                set,
                oldset,
                sigsetsize,
            } => self.sys_rt_sigprocmask(how, set, oldset, sigsetsize),
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
            LinuxSyscall::Select {
                nfds,
                readfds,
                writefds,
                exceptfds,
                timeout,
            } => self.sys_select(nfds, readfds, writefds, exceptfds, timeout),
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
            LinuxSyscall::Getpid => self.sys_getpid(),
            LinuxSyscall::Getppid => self.sys_getppid(),
            LinuxSyscall::Gettid => self.sys_gettid(),
            LinuxSyscall::Setsid => self.sys_getpid(), // unikernel: return PID as session ID
            LinuxSyscall::SetuidStub => 0,             // always root in unikernel
            LinuxSyscall::FsyncStub => 0,              // no persistent storage
            LinuxSyscall::Getuid => self.sys_getuid(),
            LinuxSyscall::Geteuid => self.sys_geteuid(),
            LinuxSyscall::Getgid => self.sys_getgid(),
            LinuxSyscall::Getegid => self.sys_getegid(),
            LinuxSyscall::Madvise { .. } => self.sys_madvise(),
            LinuxSyscall::Futex { uaddr, op, val } => self.sys_futex(uaddr, op, val),
            LinuxSyscall::SchedGetaffinity {
                cpusetsize, mask, ..
            } => self.sys_sched_getaffinity(cpusetsize, mask),
            LinuxSyscall::Uname { buf } => self.sys_uname(buf as usize),
            LinuxSyscall::ClockGettime { clockid, tp } => {
                self.sys_clock_gettime(clockid, tp as usize)
            }
            LinuxSyscall::ClockGetres { clockid, tp } => {
                self.sys_clock_getres(clockid, tp as usize)
            }
            LinuxSyscall::Fcntl { fd, cmd, arg } => self.sys_fcntl(fd, cmd, arg),
            LinuxSyscall::Dup { oldfd } => self.sys_dup(oldfd),
            LinuxSyscall::Dup2 { oldfd, newfd } => self.sys_dup2(oldfd, newfd),
            LinuxSyscall::Dup3 {
                oldfd,
                newfd,
                flags,
            } => self.sys_dup3(oldfd, newfd, flags),
            LinuxSyscall::Pipe2 { fds, flags } => self.sys_pipe2(fds, flags as i32),
            LinuxSyscall::Pipe { fds } => self.sys_pipe2(fds, 0),
            LinuxSyscall::EventFd2 { initval, flags } => {
                self.sys_eventfd2(initval as u32, flags as i32)
            }
            LinuxSyscall::Socket {
                domain,
                sock_type,
                protocol,
            } => self.sys_socket(domain, sock_type, protocol),
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
            LinuxSyscall::Sendto {
                fd,
                buf,
                len,
                flags,
                dest_addr,
                addrlen,
            } => self.sys_sendto(fd, buf, len, flags, dest_addr, addrlen),
            LinuxSyscall::Recvfrom {
                fd,
                buf,
                len,
                flags,
                src_addr,
                addrlen,
            } => self.sys_recvfrom(fd, buf, len, flags, src_addr, addrlen),
            LinuxSyscall::Setsockopt {
                fd,
                level,
                optname,
                optval,
                optlen,
            } => self.sys_setsockopt(fd, level, optname, optval, optlen),
            LinuxSyscall::Getsockopt {
                fd,
                level,
                optname,
                optval,
                optlen,
            } => self.sys_getsockopt(fd, level, optname, optval, optlen),
            LinuxSyscall::Getsockname { fd, addr, addrlen } => {
                self.sys_getsockname(fd, addr, addrlen)
            }
            LinuxSyscall::Getpeername { fd, addr, addrlen } => {
                self.sys_getpeername(fd, addr, addrlen)
            }
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
            LinuxSyscall::Fork => self.sys_fork(),
            LinuxSyscall::Vfork => self.sys_fork(),
            LinuxSyscall::Clone { flags, .. } => self.sys_clone(flags),
            LinuxSyscall::Clone3 { .. } => ENOSYS,
            LinuxSyscall::Wait4 {
                pid,
                wstatus,
                options,
                rusage,
            } => self.sys_wait4(pid, wstatus, options, rusage),
            LinuxSyscall::Execve { path, argv, envp } => self.sys_execve(path, argv, envp),
            LinuxSyscall::Kill { pid, sig } => self.sys_kill(pid, sig),
            LinuxSyscall::Tgkill { tgid, tid, sig } => self.sys_tgkill(tgid, tid, sig),
            LinuxSyscall::Nanosleep { req, rem } => self.sys_nanosleep(req, rem),
            LinuxSyscall::ClockNanosleep {
                clockid,
                flags,
                req,
                rem,
            } => self.sys_clock_nanosleep(clockid, flags, req, rem),
            LinuxSyscall::Prctl { option, arg2, .. } => self.sys_prctl(option, arg2),
            LinuxSyscall::SignalFd {
                fd,
                mask_ptr,
                sizemask,
            } => self.sys_signalfd4(fd, mask_ptr, sizemask, 0),
            LinuxSyscall::SignalFd4 {
                fd,
                mask_ptr,
                sizemask,
                flags,
            } => self.sys_signalfd4(fd, mask_ptr, sizemask, flags),
            LinuxSyscall::TimerfdCreate { clockid, flags } => {
                self.sys_timerfd_create(clockid, flags)
            }
            LinuxSyscall::TimerfdSettime {
                fd,
                flags,
                new_value,
                old_value,
            } => self.sys_timerfd_settime(fd, flags, new_value, old_value),
            LinuxSyscall::TimerfdGettime { fd, curr_value } => {
                self.sys_timerfd_gettime(fd, curr_value)
            }
            LinuxSyscall::Poll { fds, nfds, timeout } => self.sys_poll(fds, nfds, timeout),
            LinuxSyscall::Ppoll {
                fds,
                nfds,
                tmo_ptr,
                sigmask,
                ..
            } => self.sys_ppoll(fds, nfds, tmo_ptr, sigmask),
            LinuxSyscall::Readv { fd, iov, iovcnt } => self.sys_readv(fd, iov as usize, iovcnt),
            LinuxSyscall::Socketpair {
                domain,
                sock_type,
                protocol,
                sv,
            } => self.sys_socketpair(domain, sock_type, protocol, sv),
            LinuxSyscall::Getrlimit { resource, rlim } => {
                self.sys_getrlimit(resource, rlim as usize)
            }
            LinuxSyscall::Setrlimit { .. } => self.sys_setrlimit(),
            LinuxSyscall::Umask { mask } => self.sys_umask(mask),
            LinuxSyscall::Ftruncate { fd, length } => {
                if (length as i64) < 0 {
                    EINVAL
                } else {
                    self.sys_ftruncate(fd)
                }
            }
            LinuxSyscall::Renameat {
                olddirfd,
                oldpath,
                newdirfd,
                newpath,
            } => self.sys_renameat(olddirfd, oldpath, newdirfd, newpath),
            LinuxSyscall::RtSigreturn { rsp } => self.sys_rt_sigreturn(rsp),
            LinuxSyscall::Sigaltstack { ss, old_ss } => self.sys_sigaltstack(ss, old_ss),
            LinuxSyscall::Unknown { .. } => ENOSYS,
        };
        self.deliver_pending_signals();
        result
    }

    /// Linux write(2): write to a file descriptor.
    fn sys_write(&mut self, fd: i32, buf_ptr: usize, count: usize) -> i64 {
        let kind = match self.fd_table.get(&fd) {
            Some(entry) => entry.kind.clone(),
            None => return EBADF,
        };

        match kind {
            FdKind::PipeWrite { pipe_id } => {
                // POSIX: write with count == 0 is a no-op for pipes too.
                if count == 0 {
                    return 0;
                }
                // Linux default pipe capacity. Writes that would exceed
                // this return EAGAIN (consistent with the always-nonblocking
                // emulator model — see O_NONBLOCK note in sys_pipe2).
                const PIPE_BUF_CAP: usize = 65536;
                let has_reader = self
                    .fd_table
                    .values()
                    .any(|e| matches!(&e.kind, FdKind::PipeRead { pipe_id: id } if *id == pipe_id));
                // In a forked child (parent_pid != 0), the reader might be in
                // the parent process. Allow writes if the pipe buffer exists
                // (shared via fork swap) so the parent can read after recovery.
                if !has_reader {
                    let is_child = self.parent_pid != 0;
                    if !is_child || !self.pipes.contains_key(&pipe_id) {
                        return EPIPE;
                    }
                }
                let pipe_buf = match self.pipes.get_mut(&pipe_id) {
                    Some(b) => b,
                    None => return EPIPE, // pipe buffer removed (e.g. after fork recovery)
                };
                let avail = PIPE_BUF_CAP.saturating_sub(pipe_buf.len());
                // POSIX: writes <= PIPE_BUF bytes must be atomic — either
                // all bytes fit or return EAGAIN. Only writes > PIPE_BUF
                // may be partial.
                const PIPE_BUF: usize = 4096;
                let needs_block = avail == 0 || (count <= PIPE_BUF && avail < count);
                if needs_block {
                    let nonblock = self.fd_table.get(&fd).map(|e| e.nonblock).unwrap_or(true);
                    if !nonblock {
                        return self.pipe_write_blocking(fd, pipe_id, buf_ptr, count);
                    }
                    return EAGAIN;
                }
                let to_write = count.min(avail);
                let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, to_write) };
                pipe_buf.extend_from_slice(data);
                // NLL ends the borrow after the last use of pipe_buf.
                // Wake any task blocked on reading from this pipe.
                if let Some(wake) = self.wake_fn {
                    if let Some(read_fd) = self.find_pipe_read_fd(pipe_id) {
                        wake(read_fd, BLOCK_OP_READABLE);
                    }
                }
                to_write as i64
            }
            FdKind::PipeRead { .. } => EBADF,
            FdKind::EventFd { eventfd_id } => {
                if count < 8 {
                    return EINVAL;
                }

                let val = {
                    let mut val_bytes = [0u8; 8];
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            buf_ptr as *const u8,
                            val_bytes.as_mut_ptr(),
                            8,
                        );
                    }
                    u64::from_le_bytes(val_bytes)
                };
                if val == u64::MAX {
                    return EINVAL;
                }
                let state = match self.eventfds.get(&eventfd_id) {
                    Some(s) => s,
                    None => return EBADF,
                };
                if state.counter.checked_add(val).is_none()
                    || state.counter + val > 0xFFFFFFFFFFFFFFFE
                {
                    return EAGAIN;
                }
                self.eventfds.get_mut(&eventfd_id).unwrap().counter += val;
                8
            }
            FdKind::File { fid, offset, .. } => {
                // POSIX: write with count == 0 is a no-op for regular files.
                if count == 0 {
                    return 0;
                }
                let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, count) };

                match self.backend.write(fid, offset, data) {
                    Ok(n) => {
                        if let FdKind::File { ref mut offset, .. } =
                            self.fd_table.get_mut(&fd).unwrap().kind
                        {
                            *offset += n as u64;
                        }
                        n as i64
                    }
                    Err(e) => ipc_err_to_errno(e),
                }
            }
            FdKind::Socket { socket_id } => {
                let tcp_handle = match self.sockets.get(&socket_id) {
                    Some(s) => s.tcp_handle,
                    None => return EBADF,
                };
                if let Some(h) = tcp_handle {
                    if count == 0 {
                        return 0;
                    }
                    if buf_ptr == 0 {
                        return EFAULT;
                    }
                    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, count) };
                    match self.tcp.tcp_send(h, data) {
                        Ok(n) => n as i64,
                        Err(NetError::WouldBlock) => {
                            let nonblock =
                                self.fd_table.get(&fd).map(|e| e.nonblock).unwrap_or(true);
                            if !nonblock && self.block_fn.is_some() {
                                match self.block_until(BLOCK_OP_WRITABLE, fd) {
                                    BlockResult::Ready => {
                                        let data = unsafe {
                                            core::slice::from_raw_parts(buf_ptr as *const u8, count)
                                        };
                                        match self.tcp.tcp_send(h, data) {
                                            Ok(n) => return n as i64,
                                            Err(e) => return net_error_to_errno(e),
                                        }
                                    }
                                    BlockResult::Interrupted => return EAGAIN,
                                }
                            }
                            EAGAIN
                        }
                        Err(_) => EPIPE,
                    }
                } else {
                    // Stub: pretend all bytes written.
                    count.min(i64::MAX as usize) as i64
                }
            }
            FdKind::Epoll { .. } => EINVAL,
            FdKind::SignalFd { .. } => EINVAL,
            FdKind::TimerFd { .. } => EINVAL,
            // EmbeddedFs files are read-only static data.
            FdKind::EmbeddedFile { .. } => EROFS,
            FdKind::DevNull => count as i64, // discard, report success
            FdKind::DevUrandom => count as i64, // discard, report success
            FdKind::ScratchFile {
                ref path,
                ref offset,
            } => {
                let path_clone = path.clone();
                let cur_offset = *offset as usize;
                let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, count) };
                if let Some(ref mut efs) = self.embedded_fs {
                    let file_data = efs
                        .scratch
                        .entry(path_clone)
                        .or_insert_with(alloc::vec::Vec::new);
                    // Extend file if write goes past current end.
                    let end = cur_offset + count;
                    if end > file_data.len() {
                        file_data.resize(end, 0);
                    }
                    file_data[cur_offset..end].copy_from_slice(data);
                }
                // Advance offset.
                if let Some(FdEntry {
                    kind: FdKind::ScratchFile { ref mut offset, .. },
                    ..
                }) = self.fd_table.get_mut(&fd)
                {
                    *offset += count as u64;
                }
                count as i64
            }
        }
    }

    /// Linux read(2): read from a file descriptor.
    fn sys_read(&mut self, fd: i32, buf_ptr: usize, count: usize) -> i64 {
        let kind = match self.fd_table.get(&fd) {
            Some(entry) => entry.kind.clone(),
            None => return EBADF,
        };

        match kind {
            FdKind::PipeRead { pipe_id } => {
                // POSIX: read with count == 0 is a no-op for pipes too.
                if count == 0 {
                    return 0;
                }
                let buf = match self.pipes.get_mut(&pipe_id) {
                    Some(b) => b,
                    None => return 0, // EOF — pipe buffer was removed (e.g. after fork recovery)
                };
                if buf.is_empty() {
                    // Check if any writer still exists.
                    let has_writer = self.fd_table.values().any(
                        |e| matches!(&e.kind, FdKind::PipeWrite { pipe_id: id } if *id == pipe_id),
                    );
                    if has_writer {
                        // Writer exists but buffer is empty — would block.
                        let nonblock = self.fd_table.get(&fd).map(|e| e.nonblock).unwrap_or(true);
                        if nonblock || self.block_fn.is_none() {
                            return EAGAIN;
                        }

                        match self.block_until(BLOCK_OP_READABLE, fd) {
                            BlockResult::Ready => {
                                // Re-borrow after block_until releases the borrow.
                                let buf = match self.pipes.get_mut(&pipe_id) {
                                    Some(b) => b,
                                    None => return 0, // EOF
                                };
                                if buf.is_empty() {
                                    return 0; // Write end closed during wait (EOF).
                                }
                                let n = count.min(buf.len());
                                unsafe {
                                    core::ptr::copy_nonoverlapping(
                                        buf.as_ptr(),
                                        buf_ptr as *mut u8,
                                        n,
                                    );
                                }
                                buf.drain(..n);
                                // NLL ends the borrow after the last use of buf.
                                // Wake any task blocked on writing to this pipe.
                                if let Some(wake) = self.wake_fn {
                                    if let Some(write_fd) = self.find_pipe_write_fd(pipe_id) {
                                        wake(write_fd, BLOCK_OP_WRITABLE);
                                    }
                                }
                                n as i64
                            }
                            BlockResult::Interrupted => EAGAIN,
                        }
                    } else {
                        0 // EOF — write end closed
                    }
                } else {
                    let n = count.min(buf.len());
                    // Copy directly from buffer, then drain without intermediate Vec.
                    unsafe {
                        core::ptr::copy_nonoverlapping(buf.as_ptr(), buf_ptr as *mut u8, n);
                    }
                    buf.drain(..n);
                    // NLL ends the borrow after the last use of buf.
                    // Wake any task blocked on writing to this pipe.
                    if let Some(wake) = self.wake_fn {
                        if let Some(write_fd) = self.find_pipe_write_fd(pipe_id) {
                            wake(write_fd, BLOCK_OP_WRITABLE);
                        }
                    }
                    n as i64
                }
            }
            FdKind::PipeWrite { .. } => EBADF,
            FdKind::EventFd { eventfd_id } => {
                if count < 8 {
                    return EINVAL;
                }

                let state = match self.eventfds.get(&eventfd_id) {
                    Some(s) => s,
                    None => return EBADF,
                };
                if state.counter == 0 {
                    return EAGAIN;
                }
                let (val, new_counter) = if state.semaphore {
                    (1u64, state.counter - 1)
                } else {
                    (state.counter, 0u64)
                };
                let val_bytes = val.to_le_bytes();
                unsafe {
                    core::ptr::copy_nonoverlapping(val_bytes.as_ptr(), buf_ptr as *mut u8, 8);
                }
                self.eventfds.get_mut(&eventfd_id).unwrap().counter = new_counter;
                8
            }
            FdKind::File {
                fid,
                offset: file_offset,
                ..
            } => {
                // POSIX: read with count == 0 is a no-op for regular files.
                if count == 0 {
                    return 0;
                }
                // 9P count is u32; cap to avoid silent truncation on large reads.
                let capped = count.min(u32::MAX as usize) as u32;

                match self.backend.read(fid, file_offset, capped) {
                    Ok(data) => {
                        let n = data.len().min(count);
                        if n > 0 {
                            // Safety: caller guarantees buf_ptr points to valid memory of at
                            // least `count` bytes. Same trust model as sys_write.
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    data.as_ptr(),
                                    buf_ptr as *mut u8,
                                    n,
                                );
                            }
                            if let FdKind::File { ref mut offset, .. } =
                                self.fd_table.get_mut(&fd).unwrap().kind
                            {
                                *offset += n as u64;
                            }
                        }
                        n as i64
                    }
                    Err(e) => ipc_err_to_errno(e),
                }
            }
            FdKind::Socket { socket_id } => {
                let tcp_handle = match self.sockets.get(&socket_id) {
                    Some(s) => s.tcp_handle,
                    None => return EBADF,
                };
                if let Some(h) = tcp_handle {
                    if count == 0 {
                        return 0;
                    }
                    if buf_ptr == 0 {
                        return EFAULT;
                    }
                    let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, count) };
                    match self.tcp.tcp_recv(h, buf) {
                        Ok(n) => n as i64,
                        Err(NetError::WouldBlock) => {
                            let nonblock =
                                self.fd_table.get(&fd).map(|e| e.nonblock).unwrap_or(true);
                            if !nonblock && self.block_fn.is_some() {
                                match self.block_until(BLOCK_OP_READABLE, fd) {
                                    BlockResult::Ready => {
                                        let buf = unsafe {
                                            core::slice::from_raw_parts_mut(
                                                buf_ptr as *mut u8,
                                                count,
                                            )
                                        };
                                        match self.tcp.tcp_recv(h, buf) {
                                            Ok(n) => return n as i64,
                                            Err(e) => return net_error_to_errno(e),
                                        }
                                    }
                                    BlockResult::Interrupted => return EAGAIN,
                                }
                            }
                            EAGAIN
                        }
                        Err(e) => net_error_to_errno(e),
                    }
                } else {
                    // Stub: no data, return EOF.
                    0
                }
            }
            FdKind::Epoll { .. } => EINVAL,
            FdKind::SignalFd { signalfd_id } => {
                // signalfd: consume one pending signal matching the fd's mask.
                // Note: Linux supports returning multiple signalfd_siginfo structs
                // per read (up to count/128). This implementation returns exactly
                // one per call; callers must loop. Sufficient for systemd's
                // one-signal-per-iteration event loop.
                if count < 128 {
                    return EINVAL; // sizeof(signalfd_siginfo) = 128
                }
                let mask = match self.signalfds.get(&signalfd_id) {
                    Some(state) => state.mask,
                    None => return EINVAL,
                };

                // Find a pending signal that matches the signalfd's mask.
                let deliverable = self.pending_signals & mask;
                if deliverable == 0 {
                    return EAGAIN; // no matching signals pending
                }

                let bit = deliverable.trailing_zeros();
                let signum = bit + 1;
                self.pending_signals &= !(1u64 << bit);

                // Write struct signalfd_siginfo (128 bytes) to user buffer.
                // Only ssi_signo (u32 at offset 0) is set; rest zeroed.
                let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, 128) };
                buf.fill(0);
                buf[0..4].copy_from_slice(&signum.to_le_bytes());

                128 // bytes read
            }
            FdKind::TimerFd { timerfd_id } => {
                if count < 8 {
                    return EINVAL;
                }
                let state = match self.timerfds.get_mut(&timerfd_id) {
                    Some(s) => s,
                    None => return EINVAL,
                };
                if state.expiration_ns == 0 {
                    return EAGAIN; // disarmed
                }
                let now = match state.clockid {
                    CLOCK_REALTIME => self.realtime_ns,
                    _ => self.monotonic_ns,
                };
                if now < state.expiration_ns {
                    return EAGAIN; // not yet expired
                }
                // Compute expiration count.
                let elapsed = now - state.expiration_ns;
                let count_val = match elapsed.checked_div(state.interval_ns) {
                    None => {
                        // interval_ns == 0: one-shot, disarm after reading.
                        state.expiration_ns = 0;
                        1u64
                    }
                    Some(extra) => {
                        // Repeating: count how many intervals passed.
                        let count_val = 1u64.saturating_add(extra);
                        // Advance expiration past current time.
                        state.expiration_ns = state.expiration_ns.saturating_add(
                            extra.saturating_add(1).saturating_mul(state.interval_ns),
                        );
                        count_val
                    }
                };
                let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, 8) };
                buf.copy_from_slice(&count_val.to_le_bytes());
                8
            }
            FdKind::EmbeddedFile {
                ref path,
                ref offset,
            } => {
                if count == 0 {
                    return 0;
                }
                // Clone path and snapshot offset to satisfy the borrow checker
                // before mutably borrowing the fd_table entry for the offset update.
                let path_clone = path.clone();
                let file_offset = *offset;
                let n = if let Some(ref efs) = self.embedded_fs {
                    if let Some(file) = efs.get(&path_clone) {
                        let start = (file_offset as usize).min(file.data.len());
                        let end = start.saturating_add(count).min(file.data.len());
                        let n = end - start;
                        if n > 0 {
                            // Safety: buf_ptr points to valid writable user memory of at least
                            // `count` bytes — same trust model as the FdKind::File arm above.
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    file.data[start..end].as_ptr(),
                                    buf_ptr as *mut u8,
                                    n,
                                );
                            }
                        }
                        n
                    } else {
                        0 // file vanished — treat as EOF
                    }
                } else {
                    0 // no embedded_fs — should not happen if fd was created correctly
                };
                // Advance the stored offset.
                if let Some(FdEntry {
                    kind: FdKind::EmbeddedFile { ref mut offset, .. },
                    ..
                }) = self.fd_table.get_mut(&fd)
                {
                    *offset += n as u64;
                }
                n as i64
            }
            FdKind::ScratchFile {
                ref path,
                ref offset,
            } => {
                if count == 0 {
                    return 0;
                }
                let path_clone = path.clone();
                let file_offset = *offset as usize;
                let n = if let Some(ref efs) = self.embedded_fs {
                    if let Some(data) = efs.scratch.get(&path_clone) {
                        let start = file_offset.min(data.len());
                        let end = start.saturating_add(count).min(data.len());
                        let n = end - start;
                        if n > 0 {
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    data[start..end].as_ptr(),
                                    buf_ptr as *mut u8,
                                    n,
                                );
                            }
                        }
                        n
                    } else {
                        0
                    }
                } else {
                    0
                };
                if let Some(FdEntry {
                    kind: FdKind::ScratchFile { ref mut offset, .. },
                    ..
                }) = self.fd_table.get_mut(&fd)
                {
                    *offset += n as u64;
                }
                n as i64
            }
            FdKind::DevNull => 0, // EOF
            FdKind::DevUrandom => {
                // Fill buffer with random bytes from LCG-based PRNG.
                let n = count.min(256); // cap at 256 bytes per read
                let mut tmp = alloc::vec![0u8; n];
                self.fill_random(&mut tmp, buf_ptr as u64);
                unsafe {
                    core::ptr::copy_nonoverlapping(tmp.as_ptr(), buf_ptr as *mut u8, n);
                }
                n as i64
            }
        }
    }

    /// Decrement the refcount for a fid and clunk it if no references remain.
    fn release_fid(&mut self, fid: Fid) {
        let rc = self.fid_refcount.get_mut(&fid).expect("refcount missing");
        *rc -= 1;
        if *rc == 0 {
            self.fid_refcount.remove(&fid);
            let _ = self.backend.clunk(fid);
        }
    }

    /// Clean up resources for a removed fd entry. Handles all FdKind
    /// variants: releases 9P fids, frees orphaned pipe buffers, and
    /// removes orphaned eventfd state.
    ///
    /// Must be called AFTER the entry has been removed from fd_table
    /// (so the "still referenced" scans don't see the entry itself).
    fn close_fd_entry(&mut self, entry: FdEntry) {
        match entry.kind {
            FdKind::File { fid, .. } => self.release_fid(fid),
            FdKind::PipeRead { pipe_id } | FdKind::PipeWrite { pipe_id } => {
                let still_referenced = self.fd_table.values().any(|e| {
                    matches!(&e.kind, FdKind::PipeRead { pipe_id: id } | FdKind::PipeWrite { pipe_id: id } if *id == pipe_id)
                });
                if !still_referenced {
                    self.pipes.remove(&pipe_id);
                }
            }
            FdKind::EventFd { eventfd_id } => {
                let still_referenced = self.fd_table.values().any(
                    |e| matches!(&e.kind, FdKind::EventFd { eventfd_id: id } if *id == eventfd_id),
                );
                if !still_referenced {
                    self.eventfds.remove(&eventfd_id);
                }
            }
            FdKind::Socket { socket_id } => {
                let still_referenced = self.fd_table.values().any(
                    |e| matches!(&e.kind, FdKind::Socket { socket_id: id } if *id == socket_id),
                );
                if !still_referenced {
                    if let Some(state) = self.sockets.remove(&socket_id) {
                        if let Some(h) = state.tcp_handle {
                            let _ = self.tcp.tcp_close(h);
                        }
                        if let Some(h) = state.udp_handle {
                            let _ = self.tcp.udp_close(h);
                        }
                    }
                }
            }
            FdKind::Epoll { epoll_id } => {
                let still_referenced = self
                    .fd_table
                    .values()
                    .any(|e| matches!(&e.kind, FdKind::Epoll { epoll_id: id } if *id == epoll_id));
                if !still_referenced {
                    self.epolls.remove(&epoll_id);
                }
            }
            FdKind::SignalFd { signalfd_id } => {
                let still_referenced = self.fd_table.values().any(
                    |e| matches!(&e.kind, FdKind::SignalFd { signalfd_id: id } if *id == signalfd_id),
                );
                if !still_referenced {
                    self.signalfds.remove(&signalfd_id);
                }
            }
            FdKind::TimerFd { timerfd_id } => {
                let still_referenced = self.fd_table.values().any(
                    |e| matches!(&e.kind, FdKind::TimerFd { timerfd_id: id } if *id == timerfd_id),
                );
                if !still_referenced {
                    self.timerfds.remove(&timerfd_id);
                }
            }
            // EmbeddedFile/ScratchFile data lives in memory — nothing to release on close.
            FdKind::EmbeddedFile { .. } | FdKind::ScratchFile { .. } => {}
            // Device files have no resources to release.
            FdKind::DevNull | FdKind::DevUrandom => {}
        }
    }

    /// Close all file descriptors with FD_CLOEXEC set (for execve).
    fn close_cloexec_fds(&mut self) {
        let cloexec_fds: Vec<i32> = self
            .fd_table
            .iter()
            .filter(|(_, entry)| entry.flags & FD_CLOEXEC != 0)
            .map(|(&fd, _)| fd)
            .collect();

        for fd in cloexec_fds {
            if let Some(entry) = self.fd_table.remove(&fd) {
                self.close_fd_entry(entry);
            }
        }

        // Scrub closed fds from epoll interest lists.
        for epoll in self.epolls.values_mut() {
            epoll
                .interests
                .retain(|fd, _| self.fd_table.contains_key(fd));
        }
    }

    /// Reset Linuxulator state for a new process image (execve).
    fn reset_for_execve(&mut self) {
        self.arena = MemoryArena::new(self.arena_size);
        self.fs_base = 0;
        self.vm_brk_base = 0;
        self.vm_brk_current = 0;
        self.getrandom_counter = 0;
        self.exit_code = None;
        // Reset signal handlers per Linux flush_signal_handlers(t, 0):
        // - SIG_IGN handler is preserved (nohup relies on this)
        // - All other handlers reset to SIG_DFL
        // - flags, mask, and restorer are unconditionally cleared for ALL
        //   signals (including SIG_IGN ones)
        for action in &mut self.signal_handlers {
            if action.handler != SIG_IGN {
                action.handler = SIG_DFL;
            }
            action.flags = 0;
            action.mask = 0;
            action.restorer = 0;
        }
        // pending_signals preserved across exec (Linux semantics).
        self.pending_handler_signal = None;
        self.killed_by_signal = None;
        // Reset process name — Linux sets comm to the new binary's basename.
        self.process_name = [0u8; 16];
        // Reset alt stack on exec (Linux clears on exec).
        self.alt_stack_sp = 0;
        self.alt_stack_size = 0;
        self.alt_stack_flags = SS_DISABLE;
        self.on_alt_stack = false;
        self.pending_signal_return = None;
    }

    /// Deliver one pending signal at syscall boundary.
    ///
    /// Queue a signal on this process's pending bitmask.
    fn queue_signal(&mut self, sig: u32) {
        if (1..=64).contains(&sig) {
            self.pending_signals |= 1u64 << (sig - 1);
        }
    }

    /// Called at the end of dispatch_syscall. Handles SIG_DFL and
    /// SIG_IGN internally. Custom handlers are reported via
    /// pending_handler_signal for the caller to invoke.
    fn deliver_pending_signals(&mut self) {
        // If the process has already exited (e.g. via exit_group), do not
        // deliver further signals — they cannot affect wstatus anymore.
        if self.exit_code.is_some() {
            return;
        }
        if self.pending_signals == 0 {
            return;
        }

        // SIGKILL (9) always delivered regardless of mask.
        let sigkill_pending = self.pending_signals & (1u64 << (SIGKILL - 1)) != 0;
        if sigkill_pending {
            self.pending_signals &= !(1u64 << (SIGKILL - 1));
            self.exit_code = Some(0);
            self.killed_by_signal = Some(SIGKILL);
            return;
        }

        // Find lowest deliverable signal (pending AND not blocked).
        let deliverable = self.pending_signals & !self.signal_mask;
        if deliverable == 0 {
            return;
        }

        let bit = deliverable.trailing_zeros();
        let signum = bit + 1;
        self.pending_signals &= !(1u64 << bit);

        let handler = self.signal_handlers[bit as usize].handler;
        match handler {
            SIG_IGN => {}
            SIG_DFL => match default_signal_action(signum) {
                DefaultAction::Terminate => {
                    self.exit_code = Some(0);
                    self.killed_by_signal = Some(signum);
                }
                DefaultAction::Ignore => {}
            },
            _ => {
                debug_assert!(
                    self.pending_handler_signal.is_none(),
                    "pending_handler_signal overwritten: caller must consume after each dispatch_syscall"
                );
                self.pending_handler_signal = Some(signum);
            }
        }
    }

    /// Apply a successful execve: close CLOEXEC fds, reset state, build
    /// stack, set pending_execve.
    ///
    /// Separated from sys_execve so tests can exercise the success path
    /// with a synthetic LoadResult (MockBackend can't load real ELFs
    /// because vm_mmap fails).
    fn apply_execve(
        &mut self,
        load_result: &elf_loader::LoadResult,
        argv: &[alloc::string::String],
        envp: &[alloc::string::String],
    ) {
        // Capture pre-reset counter for AT_RANDOM seed mixing.
        // This provides per-execve variation even though the counter
        // is reset to 0 (matching spec: "fresh random sequence").
        let pre_reset_counter = self.getrandom_counter;

        self.close_cloexec_fds();
        self.reset_for_execve();

        // Allocate stack from the fresh arena's mmap region.
        // Caller (sys_execve) must verify arena_size >= EXECVE_STACK_SIZE
        // before calling apply_execve (before the point of no return).
        self.arena.mmap_top -= EXECVE_STACK_SIZE;
        let stack_base = self.arena.base + self.arena.mmap_top;

        // Generate deterministic random bytes for AT_RANDOM.
        // Uses the pre-reset counter as seed so each execve produces
        // distinct output, while getrandom_counter itself is reset to 0.
        let random_bytes: [u8; 16] = {
            let mut bytes = [0u8; 16];
            let mut state = pre_reset_counter
                .wrapping_add(0xDEAD_BEEF_CAFE_BABE) // non-zero seed mixing
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            for b in bytes.iter_mut() {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (state >> 33) as u8;
            }
            bytes
        };

        let argv_refs: Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
        let envp_refs: Vec<&str> = envp.iter().map(|s| s.as_str()).collect();

        let stack_slice =
            unsafe { core::slice::from_raw_parts_mut(stack_base as *mut u8, EXECVE_STACK_SIZE) };
        let sp = elf_loader::build_initial_stack(
            stack_slice,
            stack_base as u64,
            &argv_refs,
            &envp_refs,
            &load_result.auxv,
            &random_bytes,
        );

        self.pending_execve = Some(ExecveResult {
            entry_point: load_result.entry_point,
            stack_pointer: sp,
        });
    }

    /// Linux close(2): close a file descriptor.
    fn sys_close(&mut self, fd: i32) -> i64 {
        let entry = match self.fd_table.remove(&fd) {
            Some(e) => e,
            None => return EBADF,
        };
        self.close_fd_entry(entry);
        // Remove closed fd from all epoll interest lists (Linux does this
        // automatically when the last fd reference is closed).
        for epoll in self.epolls.values_mut() {
            epoll.interests.remove(&fd);
        }
        0
    }

    /// Linux fcntl(2): manipulate file descriptor flags.
    ///
    /// Supported commands:
    /// - F_GETFD (1): return fd flags (bit 0 = FD_CLOEXEC)
    /// - F_SETFD (2): set fd flags
    /// - F_GETFL (3): return file status flags (stub: returns 0)
    /// - F_SETFL (4): set file status flags (stub: no-op)
    fn sys_fcntl(&mut self, fd: i32, cmd: i32, arg: u64) -> i64 {
        const F_GETFD: i32 = 1;
        const F_SETFD: i32 = 2;
        const F_GETFL: i32 = 3;
        const F_SETFL: i32 = 4;

        match cmd {
            F_GETFD => match self.fd_table.get(&fd) {
                Some(entry) => entry.flags as i64,
                None => EBADF,
            },
            F_SETFD => match self.fd_table.get_mut(&fd) {
                Some(entry) => {
                    entry.flags = (arg as u32) & FD_CLOEXEC;
                    0
                }
                None => EBADF,
            },
            F_GETFL => match self.fd_table.get(&fd) {
                Some(entry) => {
                    if entry.nonblock {
                        O_NONBLOCK as i64
                    } else {
                        0
                    }
                }
                None => EBADF,
            },
            F_SETFL => match self.fd_table.get_mut(&fd) {
                Some(entry) => {
                    entry.nonblock = (arg as i32) & O_NONBLOCK != 0;
                    0
                }
                None => EBADF,
            },
            _ => EINVAL,
        }
    }

    /// Linux dup(2): duplicate a file descriptor.
    ///
    /// Creates a new fd pointing to the same fid as `oldfd`.
    /// The new fd gets the lowest available fd number and flags=0
    /// (CLOEXEC is not inherited per POSIX).
    ///
    /// Clone an fd entry from `oldfd` into `newfd` with the given flags,
    /// and bump the fid refcount. Caller must ensure `oldfd` exists.
    ///
    /// **Known deviation:** POSIX requires dup'd fds to share the same open
    /// file description (and thus the same offset). This implementation copies
    /// the offset by value, so reads/seeks on one fd do not advance the other.
    /// Sufficient for musl static init (fd setup), but programs relying on
    /// shared-offset semantics after dup will need a `FileDescription`
    /// indirection table (future work).
    fn dup_fd_to(&mut self, oldfd: i32, newfd: i32, fd_flags: u32) {
        let entry = self.fd_table.get(&oldfd).unwrap();
        let new_kind = entry.kind.clone();
        let src_nonblock = entry.nonblock;
        if let FdKind::File { fid, .. } = &new_kind {
            *self.fid_refcount.get_mut(fid).expect("refcount missing") += 1;
        }
        self.fd_table.insert(
            newfd,
            FdEntry {
                kind: new_kind,
                flags: fd_flags,
                nonblock: src_nonblock,
            },
        );
    }

    fn sys_dup(&mut self, oldfd: i32) -> i64 {
        if !self.fd_table.contains_key(&oldfd) {
            return EBADF;
        }
        let newfd = self.alloc_fd();
        self.dup_fd_to(oldfd, newfd, 0);
        newfd as i64
    }

    /// Linux dup2(2): duplicate a file descriptor to a specific fd.
    ///
    /// If oldfd == newfd, just validates oldfd exists and returns it.
    /// If newfd is already open, silently closes it first (clunks fid).
    ///
    /// See `dup_fd_to` for known offset-sharing deviation.
    fn sys_dup2(&mut self, oldfd: i32, newfd: i32) -> i64 {
        if newfd < 0 {
            return EBADF;
        }
        if !self.fd_table.contains_key(&oldfd) {
            return EBADF;
        }
        if oldfd == newfd {
            return newfd as i64;
        }
        // Close newfd if it's open (handles all FdKind variants).
        if let Some(existing) = self.fd_table.remove(&newfd) {
            self.close_fd_entry(existing);
        }
        self.dup_fd_to(oldfd, newfd, 0);
        newfd as i64
    }

    /// Linux dup3(2): duplicate fd with flags.
    ///
    /// Like dup2, but:
    /// - Returns EINVAL if oldfd == newfd (unlike dup2)
    /// - Accepts O_CLOEXEC flag to set FD_CLOEXEC on the new fd
    /// - Returns EINVAL for any flags other than O_CLOEXEC
    ///
    /// See `dup_fd_to` for known offset-sharing deviation.
    fn sys_dup3(&mut self, oldfd: i32, newfd: i32, flags: i32) -> i64 {
        if newfd < 0 {
            return EBADF;
        }
        if oldfd == newfd {
            return EINVAL;
        }
        // Only O_CLOEXEC is allowed; any other bits are invalid
        if flags & !O_CLOEXEC != 0 {
            return EINVAL;
        }
        if !self.fd_table.contains_key(&oldfd) {
            return EBADF;
        }
        // Close newfd if it's open (handles all FdKind variants).
        if let Some(existing) = self.fd_table.remove(&newfd) {
            self.close_fd_entry(existing);
        }
        let fd_flags = if flags & O_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        self.dup_fd_to(oldfd, newfd, fd_flags);
        newfd as i64
    }

    /// Linux pipe2(2): create a pipe with flags.
    ///
    /// Allocates a new pipe buffer and two fds (read end at `fds[0]`, write
    /// end at `fds[1]`). Writes the fd pair as two `i32` values to user
    /// memory at `fds_ptr`.
    ///
    /// `pipe(2)` is dispatched as `pipe2(fds, 0)`.
    fn sys_pipe2(&mut self, fds_ptr: u64, flags: i32) -> i64 {
        if fds_ptr == 0 {
            return EFAULT;
        }
        // O_NONBLOCK controls whether pipe reads/writes block (spin-wait)
        // or return EAGAIN immediately when no data is available.
        // Only O_CLOEXEC and O_NONBLOCK are valid flags.
        let valid_flags = O_CLOEXEC | O_NONBLOCK;
        if flags & !valid_flags != 0 {
            return EINVAL;
        }

        let fd_flags = if flags & O_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        let is_nonblock = flags & O_NONBLOCK != 0;

        // Allocate pipe buffer.
        let pipe_id = self.next_pipe_id;
        self.next_pipe_id += 1;
        self.pipes.insert(pipe_id, Vec::new());

        // Allocate two fds: read end first, then write end.
        let read_fd = self.alloc_fd();
        self.fd_table.insert(
            read_fd,
            FdEntry {
                kind: FdKind::PipeRead { pipe_id },
                flags: fd_flags,
                nonblock: is_nonblock,
            },
        );

        let write_fd = self.alloc_fd();
        self.fd_table.insert(
            write_fd,
            FdEntry {
                kind: FdKind::PipeWrite { pipe_id },
                flags: fd_flags,
                nonblock: is_nonblock,
            },
        );

        // Write the fd pair to user memory: [read_fd: i32, write_fd: i32].
        let mut fd_buf = [0u8; 8];
        fd_buf[0..4].copy_from_slice(&read_fd.to_le_bytes());
        fd_buf[4..8].copy_from_slice(&write_fd.to_le_bytes());
        self.backend.vm_write_bytes(fds_ptr, &fd_buf);

        0
    }

    /// Linux eventfd2(2): create an eventfd descriptor.
    ///
    /// Creates a single fd with an internal 64-bit counter initialized to
    /// `initval`. Supports `EFD_CLOEXEC`, `EFD_NONBLOCK`, and
    /// `EFD_SEMAPHORE` flags.
    fn sys_eventfd2(&mut self, initval: u32, flags: i32) -> i64 {
        const EFD_SEMAPHORE: i32 = 1;

        let valid_flags = O_CLOEXEC | O_NONBLOCK | EFD_SEMAPHORE;
        if flags & !valid_flags != 0 {
            return EINVAL;
        }

        let fd_flags = if flags & O_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        let semaphore = flags & EFD_SEMAPHORE != 0;

        let eventfd_id = self.next_eventfd_id;
        self.next_eventfd_id += 1;
        self.eventfds.insert(
            eventfd_id,
            EventFdState {
                counter: initval as u64,
                semaphore,
            },
        );

        let fd = self.alloc_fd();
        self.fd_table.insert(
            fd,
            FdEntry {
                kind: FdKind::EventFd { eventfd_id },
                flags: fd_flags,
                nonblock: flags & O_NONBLOCK != 0,
            },
        );
        fd as i64
    }

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

        const SOCK_STREAM: i32 = 1;
        const SOCK_DGRAM: i32 = 2;

        // Attempt to create a real TCP handle for AF_INET SOCK_STREAM sockets.
        let tcp_handle = if domain == AF_INET && base_type == SOCK_STREAM {
            self.tcp.tcp_create().ok()
        } else {
            None
        };

        // Attempt to create a real UDP handle for AF_INET SOCK_DGRAM sockets.
        let udp_handle = if domain == AF_INET && base_type == SOCK_DGRAM {
            self.tcp.udp_create().ok()
        } else {
            None
        };

        let socket_id = self.next_socket_id;
        self.next_socket_id += 1;
        self.sockets.insert(
            socket_id,
            SocketState {
                domain,
                sock_type: base_type,
                listening: false,
                accepted_once: false,
                tcp_handle,
                udp_handle,
                bound_port: 0,
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
                nonblock: flags & SOCK_NONBLOCK != 0,
            },
        );
        fd as i64
    }

    /// Helper: validate fd is a Socket, return ENOTSOCK/EBADF otherwise.
    fn require_socket(&self, fd: i32) -> Result<usize, i64> {
        match self.fd_table.get(&fd) {
            Some(FdEntry {
                kind: FdKind::Socket { socket_id },
                ..
            }) => Ok(*socket_id),
            Some(_) => Err(ENOTSOCK),
            None => Err(EBADF),
        }
    }

    /// Linux bind(2): bind socket to a local address/port.
    fn sys_bind(&mut self, fd: i32, addr: u64, addrlen: u32) -> i64 {
        let socket_id = match self.require_socket(fd) {
            Ok(id) => id,
            Err(e) => return e,
        };
        let tcp_handle = self.sockets.get(&socket_id).and_then(|s| s.tcp_handle);
        if let Some(h) = tcp_handle {
            // sockaddr_in is 16 bytes minimum (sin_family + sin_port + sin_addr + sin_zero).
            if addr == 0 || addrlen < 4 {
                return EINVAL;
            }
            // Parse port from sockaddr_in (bytes 2-3, big-endian).
            let port_bytes = unsafe { [*(addr as *const u8).add(2), *(addr as *const u8).add(3)] };
            let port = u16::from_be_bytes(port_bytes);
            return match self.tcp.tcp_bind(h, port) {
                Ok(()) => {
                    if let Some(state) = self.sockets.get_mut(&socket_id) {
                        state.bound_port = port;
                    }
                    0
                }
                Err(e) => net_error_to_errno(e),
            };
        }

        // UDP path.
        let udp_handle = self.sockets.get(&socket_id).and_then(|s| s.udp_handle);
        if let Some(h) = udp_handle {
            if addr == 0 || addrlen < 4 {
                return EINVAL;
            }
            let ptr = addr as *const u8;
            let port = u16::from_be_bytes(unsafe { [*ptr.add(2), *ptr.add(3)] });
            return match self.tcp.udp_bind(h, port) {
                Ok(()) => {
                    if let Some(state) = self.sockets.get_mut(&socket_id) {
                        state.bound_port = port;
                    }
                    0
                }
                Err(e) => net_error_to_errno(e),
            };
        }

        0 // stub no-op
    }

    /// Linux listen(2): mark socket as listening.
    fn sys_listen(&mut self, fd: i32, backlog: i32) -> i64 {
        const SOCK_STREAM: i32 = 1;
        const SOCK_SEQPACKET: i32 = 5;
        const EOPNOTSUPP: i64 = -95;
        let socket_id = match self.require_socket(fd) {
            Ok(id) => id,
            Err(e) => return e,
        };
        let tcp_handle = self.sockets.get(&socket_id).and_then(|s| s.tcp_handle);
        if let Some(state) = self.sockets.get_mut(&socket_id) {
            if state.sock_type != SOCK_STREAM && state.sock_type != SOCK_SEQPACKET {
                return EOPNOTSUPP;
            }
        }
        if let Some(h) = tcp_handle {
            match self.tcp.tcp_listen(h, backlog as usize) {
                Ok(()) => {
                    if let Some(state) = self.sockets.get_mut(&socket_id) {
                        state.listening = true;
                    }
                    0
                }
                Err(e) => net_error_to_errno(e),
            }
        } else {
            if let Some(state) = self.sockets.get_mut(&socket_id) {
                state.listening = true;
            }
            0
        }
    }

    /// Create the accepted socket state and fd entry for a successful
    /// `tcp_accept`.  Shared by the immediate and blocking-retry paths
    /// in [`sys_accept4`] to avoid code duplication.
    fn finish_tcp_accept(
        &mut self,
        accepted_handle: TcpHandle,
        domain: i32,
        sock_type: i32,
        flags: i32,
        addr: u64,
        addrlen_ptr: u64,
    ) -> i64 {
        const SOCK_CLOEXEC: i32 = 0o2000000;
        const SOCK_NONBLOCK: i32 = 0o4000;
        let new_socket_id = self.next_socket_id;
        self.next_socket_id += 1;
        // Per Linux accept4 semantics, the accepted socket's blocking
        // mode is determined solely by flags, not inherited from the listener.
        self.sockets.insert(
            new_socket_id,
            SocketState {
                domain,
                sock_type,
                listening: false,
                accepted_once: false,
                tcp_handle: Some(accepted_handle),
                udp_handle: None,
                bound_port: 0,
            },
        );
        let new_fd = self.alloc_fd();
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
                nonblock: flags & SOCK_NONBLOCK != 0,
            },
        );
        if addr != 0 {
            self.write_stub_sockaddr(addr, addrlen_ptr, domain);
        }
        new_fd as i64
    }

    /// Linux accept4(2): create a new socket fd from a listening socket.
    fn sys_accept4(&mut self, fd: i32, addr: u64, addrlen_ptr: u64, flags: i32) -> i64 {
        const SOCK_CLOEXEC: i32 = 0o2000000;
        const SOCK_NONBLOCK: i32 = 0o4000;

        let socket_id = match self.require_socket(fd) {
            Ok(id) => id,
            Err(e) => return e,
        };

        let state_snap = match self.sockets.get(&socket_id) {
            Some(s) if s.listening => (s.domain, s.sock_type, s.accepted_once, s.tcp_handle),
            Some(s) if !s.listening => return EINVAL,
            _ => return EINVAL,
        };
        let (domain, sock_type, accepted_once, parent_tcp_handle) = state_snap;

        // For the stub path EAGAIN check, read nonblock from the parent FdEntry.
        let parent_nonblock = match self.fd_table.get(&fd) {
            Some(entry) => entry.nonblock,
            None => false,
        };

        if let Some(h) = parent_tcp_handle {
            // Real TCP path: try to accept a connection.
            match self.tcp.tcp_accept(h) {
                Ok(Some(accepted_handle)) => self.finish_tcp_accept(
                    accepted_handle,
                    domain,
                    sock_type,
                    flags,
                    addr,
                    addrlen_ptr,
                ),
                Ok(None) => {
                    if !parent_nonblock && self.block_fn.is_some() {
                        // Yield to the scheduler until a connection arrives.
                        // Spurious wakes (block_until returns Ready but
                        // tcp_accept still returns None) re-enter block_until.
                        loop {
                            match self.block_until(BLOCK_OP_READABLE, fd) {
                                BlockResult::Ready => {
                                    match self.tcp.tcp_accept(h) {
                                        Ok(Some(accepted_handle)) => {
                                            return self.finish_tcp_accept(
                                                accepted_handle,
                                                domain,
                                                sock_type,
                                                flags,
                                                addr,
                                                addrlen_ptr,
                                            );
                                        }
                                        Ok(None) => {} // spurious wake — re-block
                                        Err(e) => return net_error_to_errno(e),
                                    }
                                }
                                BlockResult::Interrupted => return EAGAIN,
                            }
                        }
                    }
                    EAGAIN
                }
                Err(e) => net_error_to_errno(e),
            }
        } else {
            // Stub path (no TCP provider or non-AF_INET socket).
            // Non-blocking sockets return EAGAIN after the first accept to
            // prevent infinite accept loops in always-ready epoll stubs.
            if parent_nonblock && accepted_once {
                return EAGAIN;
            }

            // Write a stub sockaddr with the correct address family.
            self.write_stub_sockaddr(addr, addrlen_ptr, domain);

            // Create new socket state.
            let new_socket_id = self.next_socket_id;
            self.next_socket_id += 1;
            // Mark parent as having accepted once (for EAGAIN on non-blocking).
            if let Some(parent) = self.sockets.get_mut(&socket_id) {
                parent.accepted_once = true;
            }

            self.sockets.insert(
                new_socket_id,
                SocketState {
                    domain,
                    sock_type,
                    listening: false,
                    accepted_once: false,
                    tcp_handle: None,
                    udp_handle: None,
                    bound_port: 0,
                },
            );

            let new_fd = self.alloc_fd();
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
                    nonblock: flags & SOCK_NONBLOCK != 0,
                },
            );
            new_fd as i64
        }
    }

    /// Linux connect(2): connect socket to a remote address.
    fn sys_connect(&mut self, fd: i32, addr: u64, addrlen: u32) -> i64 {
        let socket_id = match self.require_socket(fd) {
            Ok(id) => id,
            Err(e) => return e,
        };
        let tcp_handle = match self.sockets.get(&socket_id) {
            Some(s) => s.tcp_handle,
            None => return EBADF,
        };
        if let Some(h) = tcp_handle {
            // sockaddr_in needs at least 8 bytes (family + port + addr).
            if addr == 0 || addrlen < 8 {
                return EINVAL;
            }
            let ptr = addr as *const u8;
            let port = u16::from_be_bytes(unsafe { [*ptr.add(2), *ptr.add(3)] });
            let ip = harmony_netstack::smoltcp::wire::Ipv4Address::new(
                unsafe { *ptr.add(4) },
                unsafe { *ptr.add(5) },
                unsafe { *ptr.add(6) },
                unsafe { *ptr.add(7) },
            );
            match self.tcp.tcp_connect(h, ip, port) {
                Ok(()) => {
                    let nonblock = self.fd_table.get(&fd).map(|e| e.nonblock).unwrap_or(true);
                    if nonblock {
                        EINPROGRESS
                    } else if self.block_fn.is_some() {
                        // Block until the handshake completes or fails.
                        // Uses BLOCK_OP_CONNECT (not BLOCK_OP_WRITABLE) so that
                        // connection failures (RST → Closed) also unblock.
                        match self.block_until(BLOCK_OP_CONNECT, fd) {
                            BlockResult::Ready => {
                                // Check whether the connect succeeded or failed.
                                // CloseWait/Closing imply the connection WAS established
                                // (peer accepted then immediately closed) — still success.
                                // Only Closed (without having been Established) means refused.
                                let tcp_state = self.tcp.tcp_state(h);
                                if tcp_state == TcpSocketState::Closed {
                                    ECONNREFUSED
                                } else {
                                    0
                                }
                            }
                            BlockResult::Interrupted => EAGAIN,
                        }
                    } else {
                        // No scheduler — return EINPROGRESS like nonblocking.
                        EINPROGRESS
                    }
                }
                Err(e) => net_error_to_errno(e),
            }
        } else if let Some(h) = self.sockets.get(&socket_id).and_then(|s| s.udp_handle) {
            // UDP connect — stores the remote endpoint, returns immediately.
            let (ip, port) = match self.parse_sockaddr_in(addr, addrlen) {
                Some(pair) => pair,
                None => return EINVAL,
            };
            match self.tcp.udp_connect(h, ip, port) {
                Ok(()) => 0,
                Err(e) => net_error_to_errno(e),
            }
        } else {
            // AF_UNIX connect: no daemon is running → ECONNREFUSED.
            // This forces musl's nscd client to fall back to file-based lookup.
            let domain = self.sockets.get(&socket_id).map(|s| s.domain).unwrap_or(0);
            if domain == 1 {
                // AF_UNIX
                -111 // ECONNREFUSED
            } else {
                0 // stub for other non-TCP sockets
            }
        }
    }

    /// Linux shutdown(2): stub — no-op.
    fn sys_shutdown(&self, fd: i32, _how: i32) -> i64 {
        match self.require_socket(fd) {
            Ok(_) => 0,
            Err(e) => e,
        }
    }

    /// Linux sendto(2): send data on a socket.
    fn sys_sendto(
        &mut self,
        fd: i32,
        buf: u64,
        len: u64,
        _flags: i32,
        dest_addr: u64,
        addrlen: u32,
    ) -> i64 {
        let socket_id = match self.require_socket(fd) {
            Ok(id) => id,
            Err(e) => return e,
        };
        let tcp_handle = match self.sockets.get(&socket_id) {
            Some(s) => s.tcp_handle,
            None => return EBADF,
        };
        if let Some(h) = tcp_handle {
            let count = len as usize;
            if count == 0 {
                return 0;
            }
            if buf == 0 {
                return EFAULT;
            }
            let data = unsafe { core::slice::from_raw_parts(buf as *const u8, count) };
            match self.tcp.tcp_send(h, data) {
                Ok(n) => n as i64,
                Err(NetError::WouldBlock) => {
                    let nonblock = self.fd_table.get(&fd).map(|e| e.nonblock).unwrap_or(true);
                    if !nonblock && self.block_fn.is_some() {
                        match self.block_until(BLOCK_OP_WRITABLE, fd) {
                            BlockResult::Ready => {
                                let data =
                                    unsafe { core::slice::from_raw_parts(buf as *const u8, count) };
                                match self.tcp.tcp_send(h, data) {
                                    Ok(n) => return n as i64,
                                    Err(e) => return net_error_to_errno(e),
                                }
                            }
                            BlockResult::Interrupted => return EAGAIN,
                        }
                    }
                    EAGAIN
                }
                Err(_) => EPIPE,
            }
        } else {
            // UDP path.
            if let Some(h) = self.sockets.get(&socket_id).and_then(|s| s.udp_handle) {
                let count = len as usize;
                if count == 0 {
                    return 0;
                }
                if buf == 0 {
                    return EFAULT;
                }
                let data = unsafe { core::slice::from_raw_parts(buf as *const u8, count) };

                if dest_addr != 0 {
                    // Explicit destination — parse and use sendto.
                    let (ip, port) = match self.parse_sockaddr_in(dest_addr, addrlen) {
                        Some(pair) => pair,
                        None => return EINVAL,
                    };
                    return match self.tcp.udp_sendto(h, data, ip, port) {
                        Ok(n) => n as i64,
                        Err(NetError::WouldBlock) => {
                            let nonblock =
                                self.fd_table.get(&fd).map(|e| e.nonblock).unwrap_or(true);
                            if !nonblock && self.block_fn.is_some() {
                                match self.block_until(BLOCK_OP_WRITABLE, fd) {
                                    BlockResult::Ready => {
                                        let data = unsafe {
                                            core::slice::from_raw_parts(buf as *const u8, count)
                                        };
                                        match self.tcp.udp_sendto(h, data, ip, port) {
                                            Ok(n) => return n as i64,
                                            Err(e) => return net_error_to_errno(e),
                                        }
                                    }
                                    BlockResult::Interrupted => return EAGAIN,
                                }
                            }
                            EAGAIN
                        }
                        Err(e) => net_error_to_errno(e),
                    };
                }

                // No destination (NULL) — must be connected.
                return match self.tcp.udp_send(h, data) {
                    Ok(n) => n as i64,
                    Err(NetError::NotConnected) => {
                        const EDESTADDRREQ: i64 = -89;
                        EDESTADDRREQ
                    }
                    Err(NetError::WouldBlock) => {
                        let nonblock = self.fd_table.get(&fd).map(|e| e.nonblock).unwrap_or(true);
                        if !nonblock && self.block_fn.is_some() {
                            match self.block_until(BLOCK_OP_WRITABLE, fd) {
                                BlockResult::Ready => {
                                    let data = unsafe {
                                        core::slice::from_raw_parts(buf as *const u8, count)
                                    };
                                    match self.tcp.udp_send(h, data) {
                                        Ok(n) => return n as i64,
                                        Err(e) => return net_error_to_errno(e),
                                    }
                                }
                                BlockResult::Interrupted => return EAGAIN,
                            }
                        }
                        EAGAIN
                    }
                    Err(e) => net_error_to_errno(e),
                };
            }

            // Stub: pretend all bytes sent.
            len.min(i64::MAX as u64) as i64
        }
    }

    /// Linux recvfrom(2): receive data from a socket.
    fn sys_recvfrom(
        &mut self,
        fd: i32,
        buf: u64,
        len: u64,
        _flags: i32,
        src: u64,
        addrlen: u64,
    ) -> i64 {
        let socket_id = match self.require_socket(fd) {
            Ok(id) => id,
            Err(e) => return e,
        };
        let tcp_handle = match self.sockets.get(&socket_id) {
            Some(s) => s.tcp_handle,
            None => return EBADF,
        };
        if let Some(h) = tcp_handle {
            let count = len as usize;
            if count == 0 {
                return 0;
            }
            if buf == 0 {
                return EFAULT;
            }
            let data = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count) };
            match self.tcp.tcp_recv(h, data) {
                Ok(n) => n as i64,
                Err(NetError::WouldBlock) => {
                    let nonblock = self.fd_table.get(&fd).map(|e| e.nonblock).unwrap_or(true);
                    if !nonblock && self.block_fn.is_some() {
                        match self.block_until(BLOCK_OP_READABLE, fd) {
                            BlockResult::Ready => {
                                let data = unsafe {
                                    core::slice::from_raw_parts_mut(buf as *mut u8, count)
                                };
                                match self.tcp.tcp_recv(h, data) {
                                    Ok(n) => return n as i64,
                                    Err(e) => return net_error_to_errno(e),
                                }
                            }
                            BlockResult::Interrupted => return EAGAIN,
                        }
                    }
                    EAGAIN
                }
                Err(e) => net_error_to_errno(e),
            }
        } else {
            // UDP path.
            if let Some(h) = self.sockets.get(&socket_id).and_then(|s| s.udp_handle) {
                let count = len as usize;
                if count == 0 {
                    return 0;
                }
                if buf == 0 {
                    return EFAULT;
                }
                let data = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count) };

                // Try connected recv first; on NotConnected, fall back to recvfrom.
                let result = match self.tcp.udp_recv(h, data) {
                    Ok(r) => Ok(r),
                    Err(NetError::NotConnected) => self.tcp.udp_recvfrom(h, data),
                    Err(e) => Err(e),
                };

                return match result {
                    Ok((n, src_addr, src_port)) => {
                        self.write_sockaddr_in(src, addrlen, src_addr, src_port);
                        n as i64
                    }
                    Err(NetError::WouldBlock) => {
                        let nonblock = self.fd_table.get(&fd).map(|e| e.nonblock).unwrap_or(true);
                        if !nonblock && self.block_fn.is_some() {
                            match self.block_until(BLOCK_OP_READABLE, fd) {
                                BlockResult::Ready => {
                                    // Retry the full UDP recv logic.
                                    let data = unsafe {
                                        core::slice::from_raw_parts_mut(buf as *mut u8, count)
                                    };
                                    let retry = match self.tcp.udp_recv(h, data) {
                                        Ok(r) => Ok(r),
                                        Err(NetError::NotConnected) => {
                                            let data = unsafe {
                                                core::slice::from_raw_parts_mut(
                                                    buf as *mut u8,
                                                    count,
                                                )
                                            };
                                            self.tcp.udp_recvfrom(h, data)
                                        }
                                        Err(e) => Err(e),
                                    };
                                    return match retry {
                                        Ok((n, src_addr, src_port)) => {
                                            self.write_sockaddr_in(
                                                src, addrlen, src_addr, src_port,
                                            );
                                            n as i64
                                        }
                                        Err(e) => net_error_to_errno(e),
                                    };
                                }
                                BlockResult::Interrupted => return EAGAIN,
                            }
                        }
                        EAGAIN
                    }
                    Err(e) => net_error_to_errno(e),
                };
            }

            // Stub: return EOF.
            self.write_stub_sockaddr(src, addrlen, 2);
            0
        }
    }

    /// Linux setsockopt(2): handles SO_KEEPALIVE; all other options are silent no-ops.
    fn sys_setsockopt(
        &mut self,
        fd: i32,
        level: i32,
        optname: i32,
        optval: u64,
        optlen: u32,
    ) -> i64 {
        let socket_id = match self.require_socket(fd) {
            Ok(id) => id,
            Err(e) => return e,
        };

        const SOL_SOCKET: i32 = 1;
        const SO_KEEPALIVE: i32 = 9;

        if level == SOL_SOCKET && optname == SO_KEEPALIVE && optlen >= 4 && optval != 0 {
            let val_bytes = unsafe { core::slice::from_raw_parts(optval as usize as *const u8, 4) };
            let val = i32::from_ne_bytes(val_bytes.try_into().unwrap());
            if let Some(h) = self.sockets.get(&socket_id).and_then(|s| s.tcp_handle) {
                let interval = if val != 0 { Some(60_000u64) } else { None };
                self.tcp.tcp_set_keepalive(h, interval);
            }
        }
        // All other options: silent success (existing behavior).
        0
    }

    /// Linux getsockopt(2): stub — write zeros to optval.
    fn sys_getsockopt(
        &self,
        fd: i32,
        _level: i32,
        _optname: i32,
        optval: u64,
        optlen_ptr: u64,
    ) -> i64 {
        match self.require_socket(fd) {
            Ok(_) => {
                if optlen_ptr != 0 {
                    let optlen_bytes =
                        unsafe { core::slice::from_raw_parts(optlen_ptr as usize as *const u8, 4) };
                    let optlen = u32::from_ne_bytes([
                        optlen_bytes[0],
                        optlen_bytes[1],
                        optlen_bytes[2],
                        optlen_bytes[3],
                    ]) as usize;
                    let optlen = optlen.min(128);
                    if optval != 0 && optlen > 0 {
                        let buf = unsafe {
                            core::slice::from_raw_parts_mut(optval as usize as *mut u8, optlen)
                        };
                        buf.fill(0);
                    }
                    // Always write back actual returned length.
                    let out = unsafe {
                        core::slice::from_raw_parts_mut(optlen_ptr as usize as *mut u8, 4)
                    };
                    out.copy_from_slice(&(optlen as u32).to_ne_bytes());
                }
                0
            }
            Err(e) => e,
        }
    }

    /// Write a stub sockaddr with the correct address family.
    /// For AF_INET: writes sockaddr_in with 127.0.0.1:0
    /// For AF_INET6: writes sockaddr_in6 with ::1, port 0
    fn write_stub_sockaddr(&self, addr: u64, addrlen_ptr: u64, domain: i32) {
        if addr == 0 || addrlen_ptr == 0 {
            return;
        }
        let addrlen_bytes =
            unsafe { core::slice::from_raw_parts(addrlen_ptr as usize as *const u8, 4) };
        let buf_len = u32::from_ne_bytes(addrlen_bytes.try_into().unwrap()) as usize;

        match domain {
            2 => {
                // AF_INET: sockaddr_in (16 bytes)
                // { sa_family: u16, sin_port: u16, sin_addr: u32, sin_zero: [u8;8] }
                let mut sa = [0u8; 16];
                sa[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
                sa[2..4].copy_from_slice(&0u16.to_be_bytes()); // port 0
                sa[4..8].copy_from_slice(&[127, 0, 0, 1]); // 127.0.0.1
                                                           // Write min(buf_len, 16) bytes, but set *addrlen to the
                                                           // actual struct size (16) per Linux convention so callers
                                                           // can detect truncation.
                let n = buf_len.min(16);
                let buf = unsafe { core::slice::from_raw_parts_mut(addr as usize as *mut u8, n) };
                buf.copy_from_slice(&sa[..n]);
                let out =
                    unsafe { core::slice::from_raw_parts_mut(addrlen_ptr as usize as *mut u8, 4) };
                out.copy_from_slice(&16u32.to_ne_bytes());
            }
            10 => {
                // AF_INET6: sockaddr_in6 (28 bytes)
                // { sa_family: u16, sin6_port: u16, sin6_flowinfo: u32, sin6_addr: [u8;16], sin6_scope_id: u32 }
                let mut sa = [0u8; 28];
                sa[0..2].copy_from_slice(&10u16.to_ne_bytes()); // AF_INET6
                sa[2..4].copy_from_slice(&0u16.to_be_bytes()); // port 0
                                                               // sin6_addr: ::1 (loopback)
                sa[23] = 1; // last byte of 16-byte addr = ::1
                let n = buf_len.min(28);
                let buf = unsafe { core::slice::from_raw_parts_mut(addr as usize as *mut u8, n) };
                buf.copy_from_slice(&sa[..n]);
                let out =
                    unsafe { core::slice::from_raw_parts_mut(addrlen_ptr as usize as *mut u8, 4) };
                out.copy_from_slice(&28u32.to_ne_bytes());
            }
            _ => {
                // Unknown domain — just zero it
                let zero_len = buf_len.min(128);
                if zero_len > 0 {
                    let buf = unsafe {
                        core::slice::from_raw_parts_mut(addr as usize as *mut u8, zero_len)
                    };
                    buf.fill(0);
                }
                let out =
                    unsafe { core::slice::from_raw_parts_mut(addrlen_ptr as usize as *mut u8, 4) };
                out.copy_from_slice(&0u32.to_ne_bytes());
            }
        }
    }

    /// Parse a `sockaddr_in` from userspace memory.
    /// Returns `None` if the pointer is null or the buffer is too short
    /// (needs at least 8 bytes: family + port + addr).
    fn parse_sockaddr_in(
        &self,
        addr: u64,
        addrlen: u32,
    ) -> Option<(harmony_netstack::smoltcp::wire::Ipv4Address, u16)> {
        if addr == 0 || addrlen < 8 {
            return None;
        }
        let ptr = addr as *const u8;
        let port = u16::from_be_bytes(unsafe { [*ptr.add(2), *ptr.add(3)] });
        let ip = harmony_netstack::smoltcp::wire::Ipv4Address::new(
            unsafe { *ptr.add(4) },
            unsafe { *ptr.add(5) },
            unsafe { *ptr.add(6) },
            unsafe { *ptr.add(7) },
        );
        Some((ip, port))
    }

    /// Write a `sockaddr_in` to userspace memory.
    /// No-op if `addr` or `addrlen_ptr` is null.
    fn write_sockaddr_in(
        &self,
        addr: u64,
        addrlen_ptr: u64,
        ip: harmony_netstack::smoltcp::wire::Ipv4Address,
        port: u16,
    ) {
        if addr == 0 || addrlen_ptr == 0 {
            return;
        }
        let addrlen_bytes = unsafe { core::slice::from_raw_parts(addrlen_ptr as *const u8, 4) };
        let buf_len = u32::from_ne_bytes(addrlen_bytes.try_into().unwrap()) as usize;
        if buf_len < 8 {
            return;
        }
        let n = buf_len.min(16);
        let sa = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, n) };
        sa[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
        sa[2..4].copy_from_slice(&port.to_be_bytes());
        sa[4..8].copy_from_slice(&ip.0);
        if n > 8 {
            sa[8..n].fill(0); // sin_zero (partial or full)
        }
        // Per Linux recvfrom(2): always write the actual struct size (16)
        // regardless of buffer size, so callers can detect truncation.
        let out = unsafe { core::slice::from_raw_parts_mut(addrlen_ptr as *mut u8, 4) };
        out.copy_from_slice(&16u32.to_ne_bytes());
    }

    /// Linux getsockname(2): return sockaddr with correct address family.
    fn sys_getsockname(&self, fd: i32, addr: u64, addrlen_ptr: u64) -> i64 {
        match self.require_socket(fd) {
            Ok(socket_id) => {
                let domain = self.sockets.get(&socket_id).map_or(2, |s| s.domain);
                self.write_stub_sockaddr(addr, addrlen_ptr, domain);
                0
            }
            Err(e) => e,
        }
    }

    /// Linux getpeername(2): return peer sockaddr with correct address family.
    /// Returns ENOTCONN for listening sockets (no peer).
    fn sys_getpeername(&self, fd: i32, addr: u64, addrlen_ptr: u64) -> i64 {
        const ENOTCONN: i64 = -107;
        match self.require_socket(fd) {
            Ok(socket_id) => {
                if self.sockets.get(&socket_id).is_some_and(|s| s.listening) {
                    return ENOTCONN;
                }
                let domain = self.sockets.get(&socket_id).map_or(2, |s| s.domain);
                self.write_stub_sockaddr(addr, addrlen_ptr, domain);
                0
            }
            Err(e) => e,
        }
    }

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
                nonblock: false,
            },
        );
        fd as i64
    }

    /// Helper: validate fd is an Epoll, return EINVAL/EBADF otherwise.
    fn require_epoll(&self, epfd: i32) -> Result<usize, i64> {
        match self.fd_table.get(&epfd) {
            Some(FdEntry {
                kind: FdKind::Epoll { epoll_id },
                ..
            }) => Ok(*epoll_id),
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

        if !self.fd_table.contains_key(&fd) {
            return EBADF;
        }
        if fd == epfd {
            return EINVAL;
        }

        const EPOLL_CTL_ADD: i32 = 1;
        const EPOLL_CTL_DEL: i32 = 3;
        const EPOLL_CTL_MOD: i32 = 2;

        match op {
            EPOLL_CTL_ADD => {
                if event_ptr == 0 {
                    return EFAULT;
                }
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
                if event_ptr == 0 {
                    return EFAULT;
                }
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
        {
            12
        }
        #[cfg(target_arch = "aarch64")]
        {
            16
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            12
        }
    }

    /// Linux epoll_wait(2): return ready fds.
    ///
    /// For TCP sockets the real readiness state is checked via the
    /// [`TcpProvider`]; all other fds are always reported as ready
    /// (existing stub behaviour).
    ///
    /// When no fds are immediately ready and `timeout != 0`, yields to the
    /// scheduler and rechecks on each wake until an fd becomes ready or the
    /// timeout expires.
    fn sys_epoll_wait(&mut self, epfd: i32, events_ptr: u64, maxevents: i32, timeout: i32) -> i64 {
        let epoll_id = match self.require_epoll(epfd) {
            Ok(id) => id,
            Err(e) => return e,
        };

        if maxevents <= 0 {
            return EINVAL;
        }

        if events_ptr == 0 {
            return EFAULT;
        }

        // Drive the network stack so TCP state is fresh.
        // monotonic_ns is in nanoseconds; tcp_poll expects milliseconds.
        let now_ms = (self.monotonic_ns / 1_000_000) as i64;
        self.tcp.tcp_poll(now_ms);

        let ready_count = self.epoll_check_once(epoll_id, events_ptr, maxevents);

        // Without poll_fn there is no way to read time — fall back to
        // the single check already performed above.
        if self.poll_fn.is_none() {
            return ready_count;
        }

        // If no events ready and blocking requested, yield to scheduler.
        if ready_count == 0 && timeout != 0 && self.block_fn.is_some() {
            let start_ms = self.poll_fn.map_or(0, |pf| pf());
            let deadline: u64 = if timeout > 0 {
                start_ms.saturating_add(timeout as u64)
            } else {
                u64::MAX // -1 = infinite wait
            };

            while let BlockResult::Ready = self.block_until(BLOCK_OP_POLL, -1) {
                // Drive the network stack.
                if let Some(pf) = self.poll_fn {
                    let now = pf() as i64;
                    self.tcp.tcp_poll(now);
                }
                let count = self.epoll_check_once(epoll_id, events_ptr, maxevents);
                if count > 0 {
                    return count;
                }
                if timeout > 0 {
                    let now = self.poll_fn.map_or(deadline, |pf| pf());
                    if now >= deadline {
                        break;
                    }
                }
                // No fds ready, not timed out — re-block.
            }
            return 0;
        }

        ready_count
    }

    /// Single-pass readiness check for epoll_wait(). Writes ready events into
    /// `events_ptr` and returns the count of ready fds.
    fn epoll_check_once(&self, epoll_id: usize, events_ptr: u64, maxevents: i32) -> i64 {
        let interests: Vec<(i32, u32, u64)> = match self.epolls.get(&epoll_id) {
            Some(s) => s
                .interests
                .iter()
                .map(|(&fd, &(m, d))| (fd, m, d))
                .collect(),
            None => return EINVAL,
        };

        const EPOLLIN: u32 = 0x001;
        const EPOLLOUT: u32 = 0x004;
        const EPOLLHUP: u32 = 0x010;

        let event_size = self.epoll_event_size();
        let mut written = 0i64;

        for (fd, mask, data) in interests {
            if written >= maxevents as i64 {
                break;
            }

            // Check if this fd maps to a TCP-backed socket.
            let tcp_handle = self.fd_table.get(&fd).and_then(|entry| {
                if let FdKind::Socket { socket_id } = &entry.kind {
                    self.sockets.get(socket_id).and_then(|s| s.tcp_handle)
                } else {
                    None
                }
            });

            // Also look up if this socket is a listener (for accept readiness).
            let is_listener = self
                .fd_table
                .get(&fd)
                .and_then(|entry| {
                    if let FdKind::Socket { socket_id } = &entry.kind {
                        self.sockets.get(socket_id).map(|s| s.listening)
                    } else {
                        None
                    }
                })
                .unwrap_or(false);

            let ready_events: u32 = if let Some(h) = tcp_handle {
                let state = self.tcp.tcp_state(h);
                let mut ev = 0u32;

                // EPOLLIN: data available, accepted connection ready, or EOF/shutdown.
                if mask & EPOLLIN != 0 {
                    if self.tcp.tcp_can_recv(h)
                        || state == TcpSocketState::CloseWait
                        || state == TcpSocketState::Closing
                        || state == TcpSocketState::Closed
                    {
                        ev |= EPOLLIN;
                    }
                    // A listening socket that transitioned to Established means
                    // a connection is ready to accept.
                    if is_listener && state == TcpSocketState::Established {
                        ev |= EPOLLIN;
                    }
                }

                // EPOLLOUT: writable when connected (not listening) and send buffer available.
                // CloseWait: remote sent FIN but local send path is still open.
                if mask & EPOLLOUT != 0
                    && !is_listener
                    && self.tcp.tcp_can_send(h)
                    && (state == TcpSocketState::Established || state == TcpSocketState::CloseWait)
                {
                    ev |= EPOLLOUT;
                }

                // EPOLLHUP: connection fully closed.
                if state == TcpSocketState::Closed || state == TcpSocketState::Closing {
                    ev |= EPOLLHUP;
                }

                ev
            } else {
                // Non-TCP fd: always ready (existing stub behaviour).
                mask
            };

            if ready_events != 0 {
                let offset = (written as usize) * event_size;
                self.write_epoll_event(events_ptr + offset as u64, ready_events, data);
                written += 1;
            }
        }
        written
    }

    // ── SignalFd ──────────────────────────────────────────────────

    /// Linux signalfd4(2): create or update a signal fd.
    fn sys_signalfd4(&mut self, fd: i32, mask_ptr: u64, sizemask: u64, flags: i32) -> i64 {
        const SFD_CLOEXEC: i32 = 0x80000;
        const SFD_NONBLOCK: i32 = 0x800;

        if sizemask != 8 {
            return EINVAL;
        }
        if flags & !(SFD_CLOEXEC | SFD_NONBLOCK) != 0 {
            return EINVAL;
        }
        if mask_ptr == 0 {
            return EFAULT;
        }

        // Read the signal mask from user memory.
        let mask_bytes = unsafe { core::slice::from_raw_parts(mask_ptr as usize as *const u8, 8) };
        let mask = u64::from_le_bytes(mask_bytes.try_into().unwrap());
        // Linux strips SIGKILL (9) and SIGSTOP (19) from signalfd masks
        // unconditionally — these signals must not be consumable via read().
        let mask = mask & !((1u64 << (SIGKILL - 1)) | (1u64 << (SIGSTOP - 1)));

        if fd == -1 {
            // Create new signalfd.
            let signalfd_id = self.next_signalfd_id;
            self.next_signalfd_id += 1;
            self.signalfds.insert(signalfd_id, SignalFdState { mask });

            let new_fd = self.alloc_fd();
            let fd_flags = if flags & SFD_CLOEXEC != 0 {
                FD_CLOEXEC
            } else {
                0
            };
            self.fd_table.insert(
                new_fd,
                FdEntry {
                    kind: FdKind::SignalFd { signalfd_id },
                    flags: fd_flags,
                    nonblock: flags & SFD_NONBLOCK != 0,
                },
            );
            new_fd as i64
        } else {
            // Update existing signalfd.
            match self.fd_table.get(&fd) {
                Some(FdEntry {
                    kind: FdKind::SignalFd { signalfd_id },
                    ..
                }) => {
                    let signalfd_id = *signalfd_id;
                    if let Some(state) = self.signalfds.get_mut(&signalfd_id) {
                        state.mask = mask;
                    }
                    fd as i64
                }
                None => EBADF,
                Some(_) => EINVAL,
            }
        }
    }

    // ── TimerFd ───────────────────────────────────────────────────

    /// Linux timerfd_create(2): create a timer file descriptor.
    /// Compute the remaining time until next timerfd expiration as (sec, nsec).
    /// Shared by timerfd_gettime and timerfd_settime's old_value output.
    fn timerfd_remaining(state: &TimerFdState, now: u64) -> (i64, i64) {
        if state.expiration_ns == 0 {
            return (0, 0);
        }
        if now < state.expiration_ns {
            let remaining = state.expiration_ns - now;
            return (
                (remaining / 1_000_000_000) as i64,
                (remaining % 1_000_000_000) as i64,
            );
        }
        // Expired: one-shot (interval=0) or repeating.
        let elapsed = now - state.expiration_ns;
        match elapsed.checked_div(state.interval_ns) {
            None => (0, 0), // interval_ns==0: one-shot expired
            Some(extra) => {
                let next = state
                    .expiration_ns
                    .saturating_add(extra.saturating_add(1).saturating_mul(state.interval_ns));
                let to_next = next.saturating_sub(now);
                (
                    (to_next / 1_000_000_000) as i64,
                    (to_next % 1_000_000_000) as i64,
                )
            }
        }
    }

    fn sys_timerfd_create(&mut self, clockid: i32, flags: i32) -> i64 {
        const TFD_CLOEXEC: i32 = 0x80000;
        const TFD_NONBLOCK: i32 = 0x800;

        if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
            return EINVAL;
        }
        if flags & !(TFD_CLOEXEC | TFD_NONBLOCK) != 0 {
            return EINVAL;
        }

        let timerfd_id = self.next_timerfd_id;
        self.next_timerfd_id += 1;
        self.timerfds.insert(
            timerfd_id,
            TimerFdState {
                clockid,
                expiration_ns: 0,
                interval_ns: 0,
            },
        );

        let fd = self.alloc_fd();
        let fd_flags = if flags & TFD_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        self.fd_table.insert(
            fd,
            FdEntry {
                kind: FdKind::TimerFd { timerfd_id },
                flags: fd_flags,
                nonblock: flags & TFD_NONBLOCK != 0,
            },
        );
        fd as i64
    }

    /// Linux timerfd_settime(2): arm or disarm a timerfd.
    fn sys_timerfd_settime(
        &mut self,
        fd: i32,
        flags: i32,
        new_value_ptr: u64,
        old_value_ptr: u64,
    ) -> i64 {
        const TFD_TIMER_ABSTIME: i32 = 1;

        if flags & !TFD_TIMER_ABSTIME != 0 {
            return EINVAL;
        }

        let timerfd_id = match self.fd_table.get(&fd) {
            Some(FdEntry {
                kind: FdKind::TimerFd { timerfd_id },
                ..
            }) => *timerfd_id,
            None => return EBADF,
            Some(_) => return EINVAL,
        };

        if new_value_ptr == 0 {
            return EFAULT;
        }

        // Read and validate ALL fields BEFORE mutating state.
        let its = unsafe { core::slice::from_raw_parts(new_value_ptr as usize as *const u8, 32) };
        let interval_sec = i64::from_le_bytes(its[0..8].try_into().unwrap());
        let interval_nsec = i64::from_le_bytes(its[8..16].try_into().unwrap());
        let value_sec = i64::from_le_bytes(its[16..24].try_into().unwrap());
        let value_nsec = i64::from_le_bytes(its[24..32].try_into().unwrap());

        if interval_sec < 0 || !(0..1_000_000_000).contains(&interval_nsec) {
            return EINVAL;
        }
        // Note: interval_sec == i64::MAX saturates to u64::MAX via saturating_mul;
        // the resulting timer fires once and then effectively never repeats.
        let new_interval_ns = (interval_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(interval_nsec as u64);

        let is_disarm = value_sec == 0 && value_nsec == 0;
        if !is_disarm && (value_sec < 0 || !(0..1_000_000_000).contains(&value_nsec)) {
            return EINVAL;
        }
        let value_ns = if is_disarm {
            0
        } else {
            (value_sec as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add(value_nsec as u64)
        };

        // Write old value if requested — BEFORE modifying state.
        // Must match timerfd_gettime semantics: for expired repeating timers,
        // report time until next tick, not 0.
        if old_value_ptr != 0 {
            let state = self.timerfds.get(&timerfd_id).unwrap();
            let now = match state.clockid {
                CLOCK_REALTIME => self.realtime_ns,
                _ => self.monotonic_ns,
            };
            let (old_val_sec, old_val_nsec) = Self::timerfd_remaining(state, now);
            let old_int_sec = (state.interval_ns / 1_000_000_000) as i64;
            let old_int_nsec = (state.interval_ns % 1_000_000_000) as i64;
            let buf =
                unsafe { core::slice::from_raw_parts_mut(old_value_ptr as usize as *mut u8, 32) };
            buf[0..8].copy_from_slice(&old_int_sec.to_le_bytes());
            buf[8..16].copy_from_slice(&old_int_nsec.to_le_bytes());
            buf[16..24].copy_from_slice(&old_val_sec.to_le_bytes());
            buf[24..32].copy_from_slice(&old_val_nsec.to_le_bytes());
        }

        // Now apply the new timer settings (point of no return).
        let state = match self.timerfds.get_mut(&timerfd_id) {
            Some(s) => s,
            None => return EINVAL,
        };
        state.interval_ns = new_interval_ns;

        if is_disarm {
            state.expiration_ns = 0;
        } else if flags & TFD_TIMER_ABSTIME != 0 {
            state.expiration_ns = value_ns;
        } else {
            let now = match state.clockid {
                CLOCK_REALTIME => self.realtime_ns,
                _ => self.monotonic_ns,
            };
            state.expiration_ns = now.saturating_add(value_ns);
        }

        0
    }

    /// Linux timerfd_gettime(2): query the current timer settings.
    fn sys_timerfd_gettime(&self, fd: i32, curr_value_ptr: u64) -> i64 {
        let timerfd_id = match self.fd_table.get(&fd) {
            Some(FdEntry {
                kind: FdKind::TimerFd { timerfd_id },
                ..
            }) => *timerfd_id,
            None => return EBADF,
            Some(_) => return EINVAL,
        };

        if curr_value_ptr == 0 {
            return EFAULT;
        }

        let state = match self.timerfds.get(&timerfd_id) {
            Some(s) => s,
            None => return EINVAL,
        };

        // Compute remaining time until next expiration.
        let now = match state.clockid {
            CLOCK_REALTIME => self.realtime_ns,
            _ => self.monotonic_ns,
        };
        let (value_sec, value_nsec) = Self::timerfd_remaining(state, now);

        let interval_sec = (state.interval_ns / 1_000_000_000) as i64;
        let interval_nsec = (state.interval_ns % 1_000_000_000) as i64;

        // Write struct itimerspec.
        let buf =
            unsafe { core::slice::from_raw_parts_mut(curr_value_ptr as usize as *mut u8, 32) };
        buf[0..8].copy_from_slice(&interval_sec.to_le_bytes());
        buf[8..16].copy_from_slice(&interval_nsec.to_le_bytes());
        buf[16..24].copy_from_slice(&value_sec.to_le_bytes());
        buf[24..32].copy_from_slice(&value_nsec.to_le_bytes());

        0
    }

    // ── Process management ────────────────────────────────────────

    /// Create a child Linuxulator with cloned state for fork.
    ///
    /// Returns `None` if the backend or TCP provider does not support fork.
    fn create_child(&mut self, child_pid: i32) -> Option<Linuxulator<B, T>> {
        let child_backend = self.backend.fork_backend()?;
        let child_tcp = self.tcp.tcp_fork()?;
        // Child socket state: sockets with tcp_handle are not forked (TCP
        // handles are not duplicable). Clone the socket map but clear
        // tcp_handles so child sockets become stubs.
        let child_sockets = self
            .sockets
            .iter()
            .map(|(&id, s)| {
                (
                    id,
                    SocketState {
                        domain: s.domain,
                        sock_type: s.sock_type,
                        listening: s.listening,
                        accepted_once: s.accepted_once,
                        tcp_handle: None,
                        udp_handle: None,
                        bound_port: s.bound_port,
                    },
                )
            })
            .collect();
        let mut child = Linuxulator {
            backend: child_backend,
            tcp: child_tcp,
            fd_table: self.fd_table.clone(),
            next_fid: self.next_fid,
            exit_code: None,
            arena: MemoryArena::new(self.arena_size),
            fs_base: self.fs_base,
            vm_brk_base: 0,
            vm_brk_current: 0,
            getrandom_counter: 0, // reset for distinct random output
            cwd: self.cwd.clone(),
            monotonic_ns: self.monotonic_ns,
            realtime_ns: self.realtime_ns,
            fid_refcount: self.fid_refcount.clone(),
            // pipes and eventfds will be moved via mem::swap
            pipes: BTreeMap::new(),
            next_pipe_id: self.next_pipe_id,
            eventfds: BTreeMap::new(),
            next_eventfd_id: self.next_eventfd_id,
            sockets: child_sockets,
            next_socket_id: self.next_socket_id,
            epolls: self.epolls.clone(),
            next_epoll_id: self.next_epoll_id,
            pid: child_pid,
            parent_pid: self.pid,
            next_child_pid: self.next_child_pid,
            children: Vec::new(),
            exited_children: Vec::new(),
            arena_size: self.arena_size,
            pending_execve: None,
            signal_handlers: self.signal_handlers,
            signal_mask: self.signal_mask,
            pending_signals: 0,
            pending_handler_signal: None,
            killed_by_signal: None,
            process_name: self.process_name,
            signalfds: self.signalfds.clone(),
            next_signalfd_id: self.next_signalfd_id,
            timerfds: self.timerfds.clone(),
            next_timerfd_id: self.next_timerfd_id,
            umask_val: self.umask_val,
            alt_stack_sp: self.alt_stack_sp,
            alt_stack_size: self.alt_stack_size,
            alt_stack_flags: self.alt_stack_flags,
            on_alt_stack: false,
            pending_signal_return: None,
            // EmbeddedFs contains only &'static references — clone is cheap.
            embedded_fs: self.embedded_fs.clone(),
            // Function pointer — copy to child so blocking ops work in forked processes.
            poll_fn: self.poll_fn,
            // Scheduler callbacks — inherited by child so blocking ops use the same scheduler.
            block_fn: self.block_fn,
            wake_fn: self.wake_fn,
        };
        // Move shared pipe/eventfd state to child
        core::mem::swap(&mut self.pipes, &mut child.pipes);
        core::mem::swap(&mut self.eventfds, &mut child.eventfds);
        Some(child)
    }

    /// Linux fork(2): create child process (sequential model).
    ///
    /// Creates a child Linuxulator and pushes it as an active child.
    /// The child's pipes/eventfds are shared with the parent (moved
    /// for the duration of child execution). Returns child_pid to the
    /// parent. The caller should check `pending_fork_child()` and
    /// dispatch to the child with return value 0.
    fn sys_fork(&mut self) -> i64 {
        // Recover any previously-exited child before creating a new one.
        // This ensures pipes/eventfds are back with the parent before
        // the next mem::swap in create_child.
        self.recover_child_state();

        // Sequential model: only one active child at a time.
        if self
            .children
            .last()
            .is_some_and(|c| c.linuxulator.exit_code.is_none())
        {
            return EAGAIN;
        }

        let child_pid = self.next_child_pid;
        self.next_child_pid += 1;

        let child = match self.create_child(child_pid) {
            Some(c) => c,
            None => return ENOSYS, // backend does not support fork
        };
        self.children.push(ChildProcess {
            pid: child_pid,
            linuxulator: child,
        });

        child_pid as i64
    }

    /// Linux clone(2): validate flags and delegate to fork.
    ///
    /// Accepts SIGCHLD (17) optionally combined with CLONE_CHILD_SETTID
    /// and CLONE_CHILD_CLEARTID (musl's fork() wrapper). Threading
    /// flags (CLONE_VM, CLONE_THREAD, CLONE_FILES) return ENOSYS.
    fn sys_clone(&mut self, flags: u64) -> i64 {
        const CLONE_VM: u64 = 0x00000100;
        const CLONE_FILES: u64 = 0x00000400;
        const CLONE_THREAD: u64 = 0x00010000;
        const CLONE_CHILD_SETTID: u64 = 0x01000000;
        const CLONE_CHILD_CLEARTID: u64 = 0x00200000;

        // Reject threading flags
        if flags & (CLONE_VM | CLONE_FILES | CLONE_THREAD) != 0 {
            return ENOSYS;
        }

        // Accept SIGCHLD with optional TID flags. CLONE_CHILD_SETTID and
        // CLONE_CHILD_CLEARTID are accepted but not acted upon — the TID
        // writes are not performed. This is safe for fork() because musl's
        // waitpid uses SIGCHLD-based waiting for child processes, not
        // futex-based TID polling (which is only used for threads).
        let sig = flags & 0xFF;
        let known_flags = SIGCHLD_NUM as u64 | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;
        if sig != SIGCHLD_NUM as u64 || (flags & !known_flags) != 0 {
            return ENOSYS;
        }

        self.sys_fork()
    }

    /// Linux wait4(2): wait for a child process to exit.
    ///
    /// In the sequential model, children run to completion before the
    /// parent resumes, so exited children are always available in
    /// `self.exited_children` by the time the parent calls wait4.
    ///
    /// pid semantics:
    /// - pid > 0: wait for specific child
    /// - pid == -1: wait for any child
    /// - pid == 0 or pid < -1: not supported (ENOSYS)
    ///
    /// options:
    /// - WNOHANG (1): return 0 immediately if no child has exited
    /// - Without WNOHANG: return ECHILD if no exited children available
    ///
    /// wstatus format: (exit_code & 0xFF) << 8 (normal exit, no signal)
    fn sys_wait4(&mut self, pid: i32, wstatus_ptr: u64, options: i32, rusage_ptr: u64) -> i64 {
        const WNOHANG: i32 = 1;

        if pid == 0 || pid < -1 {
            return ENOSYS; // process group wait not supported
        }

        // Reject unsupported options (WUNTRACED, WCONTINUED, __WALL, etc.)
        if options & !WNOHANG != 0 {
            return EINVAL;
        }

        // Ensure any recently-exited child is recovered first.
        self.recover_child_state();

        // Check if the requested pid is a known child (active or exited).
        // For pid == -1 (any child), check if any children exist at all.
        // For pid > 0, check if that specific pid is a known child.
        let has_matching_children = if pid == -1 {
            !self.children.is_empty() || !self.exited_children.is_empty()
        } else {
            self.children.iter().any(|c| c.pid == pid)
                || self.exited_children.iter().any(|&(p, _, _)| p == pid)
        };

        let idx = if pid == -1 {
            // Any child — return oldest exited child (FIFO, matching Linux).
            if self.exited_children.is_empty() {
                None
            } else {
                Some(0)
            }
        } else {
            // Specific child
            self.exited_children.iter().position(|&(p, _, _)| p == pid)
        };

        let idx = match idx {
            Some(i) => i,
            None => {
                if !has_matching_children {
                    // Requested pid is not a known child — ECHILD.
                    return ECHILD;
                }
                if options & WNOHANG != 0 {
                    return 0; // child exists but hasn't exited yet
                }
                return ECHILD; // no exited children available
            }
        };

        let (child_pid, exit_code, killed_by) = self.exited_children.remove(idx);

        // Write wstatus if pointer is non-null.
        // Linux wstatus format for normal exit: (code & 0xFF) << 8
        // Linux wstatus format for signal death: (sig & 0x7F)
        if wstatus_ptr != 0 {
            let wstatus = match killed_by {
                Some(sig) => sig & 0x7F,
                None => ((exit_code & 0xFF) as u32) << 8,
            };
            let buf =
                unsafe { core::slice::from_raw_parts_mut(wstatus_ptr as usize as *mut u8, 4) };
            buf.copy_from_slice(&wstatus.to_ne_bytes());
        }

        // Zero rusage if provided — resource tracking not implemented.
        if rusage_ptr != 0 {
            let buf =
                unsafe { core::slice::from_raw_parts_mut(rusage_ptr as usize as *mut u8, 144) };
            buf.fill(0);
        }

        child_pid as i64
    }

    /// Linux kill(2): send a signal to a process.
    fn sys_kill(&mut self, pid: i32, sig: i32) -> i64 {
        if !(0..=64).contains(&sig) {
            return EINVAL;
        }
        // pid < 0: process group signaling (not supported).
        // pid == -1 means all processes, pid < -1 means group abs(pid).
        if pid < 0 {
            return ENOSYS;
        }
        // pid == 0: send to own process group — treat as self-signal
        // (matches libc raise() which uses kill(0, sig)).
        // Non-self PIDs return ESRCH (standard "no such process" —
        // callers like systemd use kill(pid, 0) for alive-checks and
        // expect ESRCH). Cross-process signaling is not yet implemented.
        if pid != 0 && pid != self.pid {
            return ESRCH;
        }
        if sig == 0 {
            return 0; // null signal — process exists check
        }
        self.queue_signal(sig as u32);
        0
    }

    /// Linux tgkill(2): send signal to a specific thread.
    fn sys_tgkill(&mut self, tgid: i32, tid: i32, sig: i32) -> i64 {
        if tgid <= 0 || tid <= 0 {
            return EINVAL;
        }
        if !(0..=64).contains(&sig) {
            return EINVAL;
        }
        if tgid != self.pid || tid != self.pid {
            return ESRCH;
        }
        if sig == 0 {
            return 0;
        }
        self.queue_signal(sig as u32);
        0
    }

    /// Linux nanosleep(2): sleep for the specified duration.
    ///
    /// In the sans-I/O model, sleep advances the monotonic clock by the
    /// requested duration and returns immediately (no real blocking).
    fn sys_nanosleep(&mut self, req_ptr: u64, rem_ptr: u64) -> i64 {
        // nanosleep always sleeps on CLOCK_MONOTONIC with relative time.
        self.sys_clock_nanosleep(CLOCK_MONOTONIC, 0, req_ptr, rem_ptr)
    }

    /// Linux clock_nanosleep(2): sleep on a specific clock.
    ///
    /// Supports both relative (flags=0) and absolute (TIMER_ABSTIME)
    /// sleep. For absolute, computes delta from current clock value.
    fn sys_clock_nanosleep(
        &mut self,
        clockid: i32,
        flags: i32,
        req_ptr: u64,
        _rem_ptr: u64,
    ) -> i64 {
        if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
            return EINVAL;
        }

        const TIMER_ABSTIME: i32 = 1;
        if flags & !TIMER_ABSTIME != 0 {
            return EINVAL;
        }
        if flags & TIMER_ABSTIME != 0 {
            // Absolute time: compute delta from current clock value.
            if req_ptr == 0 {
                return EFAULT;
            }
            let req_bytes =
                unsafe { core::slice::from_raw_parts(req_ptr as usize as *const u8, 16) };
            let abs_sec = i64::from_le_bytes(req_bytes[0..8].try_into().unwrap());
            let abs_nsec = i64::from_le_bytes(req_bytes[8..16].try_into().unwrap());
            if abs_sec < 0 || !(0..1_000_000_000).contains(&abs_nsec) {
                return EINVAL;
            }
            let abs_ns = (abs_sec as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add(abs_nsec as u64);
            let now = match clockid {
                CLOCK_REALTIME => self.realtime_ns,
                _ => self.monotonic_ns,
            };
            // If target is already in the past, return immediately.
            let delta_ns = abs_ns.saturating_sub(now);
            // Advance the clock we're sleeping on (not always monotonic).
            match clockid {
                CLOCK_REALTIME => {
                    self.realtime_ns = self.realtime_ns.wrapping_add(delta_ns);
                }
                _ => {
                    self.monotonic_ns = self.monotonic_ns.wrapping_add(delta_ns);
                }
            }
            return 0;
        }

        // Relative sleep: advance the requested clock by the duration.
        if req_ptr == 0 {
            return EFAULT;
        }
        let req_bytes = unsafe { core::slice::from_raw_parts(req_ptr as usize as *const u8, 16) };
        let tv_sec = i64::from_le_bytes(req_bytes[0..8].try_into().unwrap());
        let tv_nsec = i64::from_le_bytes(req_bytes[8..16].try_into().unwrap());
        if tv_sec < 0 || !(0..1_000_000_000).contains(&tv_nsec) {
            return EINVAL;
        }
        let duration_ns = (tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(tv_nsec as u64);
        match clockid {
            CLOCK_REALTIME => {
                self.realtime_ns = self.realtime_ns.wrapping_add(duration_ns);
            }
            _ => {
                self.monotonic_ns = self.monotonic_ns.wrapping_add(duration_ns);
            }
        }
        0
    }

    /// Linux prctl(2): process control operations.
    ///
    /// Supports PR_SET_NAME and PR_GET_NAME. Other options return 0
    /// (no-op stub) to avoid breaking programs that probe capabilities.
    fn sys_prctl(&mut self, option: i32, arg2: u64) -> i64 {
        const PR_SET_NAME: i32 = 15;
        const PR_GET_NAME: i32 = 16;

        match option {
            PR_SET_NAME => {
                if arg2 == 0 {
                    return EFAULT;
                }
                // Read byte-by-byte up to 15 chars (avoids reading past
                // short buffers near page boundaries). Always null-terminates
                // at [15]. Matches Linux kernel's strncpy_from_user semantics.
                self.process_name = [0u8; 16];
                let base = arg2 as usize;
                for i in 0..15 {
                    let b = unsafe { *((base + i) as *const u8) };
                    if b == 0 {
                        break;
                    }
                    self.process_name[i] = b;
                }
                0
            }
            PR_GET_NAME => {
                if arg2 == 0 {
                    return EFAULT;
                }
                let dst = unsafe { core::slice::from_raw_parts_mut(arg2 as usize as *mut u8, 16) };
                dst.copy_from_slice(&self.process_name);
                0
            }
            _ => 0, // stub: accept unknown options silently
        }
    }

    /// Linux fstat(2): get file status.
    fn sys_fstat(&mut self, fd: i32, statbuf_ptr: usize) -> i64 {
        if statbuf_ptr == 0 {
            return EFAULT;
        }
        let kind = match self.fd_table.get(&fd) {
            Some(entry) => entry.kind.clone(),
            None => return EBADF,
        };
        match kind {
            FdKind::PipeRead { .. } | FdKind::PipeWrite { .. } => {
                // Synthetic stat with S_IFIFO — programs like bash use this
                // to detect pipe fds.
                write_linux_stat_with_mode(
                    statbuf_ptr,
                    &FileStat {
                        qpath: fd as u64,
                        name: alloc::sync::Arc::from("pipe"),
                        size: 0,
                        file_type: FileType::Regular, // ignored — mode_override used
                    },
                    Some(0o010000 | 0o644), // S_IFIFO | rw-r--r--
                );
                0
            }
            FdKind::EventFd { .. } => {
                // Synthetic stat with S_IFREG and size 0.
                write_linux_stat(
                    statbuf_ptr,
                    &FileStat {
                        qpath: fd as u64,
                        name: alloc::sync::Arc::from("eventfd"),
                        size: 0,
                        file_type: FileType::Regular,
                    },
                );
                0
            }
            FdKind::Socket { socket_id } => {
                let stat = FileStat {
                    qpath: socket_id as u64,
                    name: alloc::sync::Arc::from("socket"),
                    size: 0,
                    file_type: FileType::Regular, // ignored — mode_override used
                };
                // S_IFSOCK = 0o140000
                write_linux_stat_with_mode(statbuf_ptr, &stat, Some(0o140644));
                0
            }
            FdKind::Epoll { epoll_id } => {
                let stat = FileStat {
                    qpath: epoll_id as u64,
                    name: alloc::sync::Arc::from("epoll"),
                    size: 0,
                    file_type: FileType::Regular,
                };
                write_linux_stat(statbuf_ptr, &stat);
                0
            }
            FdKind::SignalFd { signalfd_id } => {
                let stat = FileStat {
                    qpath: signalfd_id as u64,
                    name: alloc::sync::Arc::from("signalfd"),
                    size: 0,
                    file_type: FileType::Regular,
                };
                write_linux_stat(statbuf_ptr, &stat);
                0
            }
            FdKind::TimerFd { timerfd_id } => {
                let stat = FileStat {
                    qpath: timerfd_id as u64,
                    name: alloc::sync::Arc::from("timerfd"),
                    size: 0,
                    file_type: FileType::Regular,
                };
                write_linux_stat(statbuf_ptr, &stat);
                0
            }
            FdKind::File { fid, .. } => match self.backend.stat(fid) {
                Ok(stat) => {
                    write_linux_stat(statbuf_ptr, &stat);
                    0
                }
                Err(e) => ipc_err_to_errno(e),
            },
            FdKind::EmbeddedFile { ref path, .. } => {
                let path_clone = path.clone();
                if let Some(ref efs) = self.embedded_fs {
                    if let Some(file) = efs.get(&path_clone) {
                        let mode: u32 = if file.executable {
                            0o100755 // S_IFREG | rwxr-xr-x
                        } else {
                            0o100644 // S_IFREG | rw-r--r--
                        };
                        let size = file.data.len() as u64;
                        let stat = FileStat {
                            qpath: 0,
                            name: alloc::sync::Arc::from(path_clone.as_str()),
                            size,
                            file_type: FileType::Regular,
                        };
                        write_linux_stat_with_mode(statbuf_ptr, &stat, Some(mode));
                        return 0;
                    }
                }
                ENOENT
            }
            FdKind::ScratchFile { ref path, .. } => {
                let path_clone = path.clone();
                let size = self
                    .embedded_fs
                    .as_ref()
                    .and_then(|efs| efs.scratch.get(&path_clone))
                    .map_or(0, |d| d.len() as u64);
                let stat = FileStat {
                    qpath: 0,
                    name: alloc::sync::Arc::from(path_clone.as_str()),
                    size,
                    file_type: FileType::Regular,
                };
                write_linux_stat_with_mode(statbuf_ptr, &stat, Some(0o100644));
                0
            }
            FdKind::DevNull | FdKind::DevUrandom => {
                // S_IFCHR | 0o666 — character device, rw for all
                let stat = FileStat {
                    qpath: fd as u64,
                    name: alloc::sync::Arc::from("dev"),
                    size: 0,
                    file_type: FileType::Regular, // ignored — mode_override used
                };
                write_linux_stat_with_mode(statbuf_ptr, &stat, Some(0o020666));
                0
            }
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
        let path = if dirfd == AT_FDCWD || raw_path.starts_with('/') {
            self.resolve_path(&raw_path)
        } else if self.fd_table.contains_key(&dirfd) {
            // dirfd-relative: not yet supported
            return ENOSYS;
        } else {
            return EBADF;
        };

        // Check EmbeddedFs first — if the path is a registered embedded file
        // (static or scratch), open it without a 9P round-trip.
        const O_CREAT: i32 = 0o100;
        const O_TRUNC: i32 = 0o1000;
        let is_nonblock = flags & O_NONBLOCK != 0;
        let (is_static, is_scratch, efs_present) = match self.embedded_fs {
            Some(ref efs) => (
                efs.get(&path).is_some(),
                efs.scratch.contains_key(&path),
                true,
            ),
            None => (false, false, false),
        };
        if is_static && !is_scratch {
            // Static embedded files are read-only.
            if flags & 0x03 != 0 {
                return EROFS;
            }
            let fd_flags = if flags & O_CLOEXEC != 0 {
                FD_CLOEXEC
            } else {
                0
            };
            let fd = self.alloc_fd();
            self.fd_table.insert(
                fd,
                FdEntry {
                    kind: FdKind::EmbeddedFile { path, offset: 0 },
                    flags: fd_flags,
                    nonblock: is_nonblock,
                },
            );
            return fd as i64;
        }
        if is_scratch {
            // Scratch file — writable.
            if flags & O_TRUNC != 0 {
                if let Some(ref mut efs) = self.embedded_fs {
                    efs.write_scratch(&path, alloc::vec::Vec::new());
                }
            }
            let fd_flags = if flags & O_CLOEXEC != 0 {
                FD_CLOEXEC
            } else {
                0
            };
            let fd = self.alloc_fd();
            self.fd_table.insert(
                fd,
                FdEntry {
                    kind: FdKind::ScratchFile { path, offset: 0 },
                    flags: fd_flags,
                    nonblock: is_nonblock,
                },
            );
            return fd as i64;
        }

        // Handle synthetic device files.
        match path.as_str() {
            "/dev/null" => {
                let fd_flags = if flags & O_CLOEXEC != 0 {
                    FD_CLOEXEC
                } else {
                    0
                };
                let fd = self.alloc_fd();
                self.fd_table.insert(
                    fd,
                    FdEntry {
                        kind: FdKind::DevNull,
                        flags: fd_flags,
                        nonblock: is_nonblock,
                    },
                );
                return fd as i64;
            }
            "/dev/urandom" | "/dev/random" => {
                let fd_flags = if flags & O_CLOEXEC != 0 {
                    FD_CLOEXEC
                } else {
                    0
                };
                let fd = self.alloc_fd();
                self.fd_table.insert(
                    fd,
                    FdEntry {
                        kind: FdKind::DevUrandom,
                        flags: fd_flags,
                        nonblock: is_nonblock,
                    },
                );
                return fd as i64;
            }
            _ => {}
        }

        // When EmbeddedFs is configured, it IS the root filesystem.
        // O_CREAT: create a new scratch file if the parent directory exists.
        if efs_present && flags & O_CREAT != 0 {
            // Verify parent directory exists in the filesystem.
            let parent = path.rfind('/').map(|i| &path[..i]).unwrap_or("");
            let parent_exists = parent.is_empty()
                || parent == "/"
                || self
                    .embedded_fs
                    .as_ref()
                    .is_some_and(|efs| efs.exists(parent));
            if parent_exists {
                if let Some(ref mut efs) = self.embedded_fs {
                    efs.write_scratch(&path, alloc::vec::Vec::new());
                }
                let fd_flags = if flags & O_CLOEXEC != 0 {
                    FD_CLOEXEC
                } else {
                    0
                };
                let fd = self.alloc_fd();
                self.fd_table.insert(
                    fd,
                    FdEntry {
                        kind: FdKind::ScratchFile { path, offset: 0 },
                        flags: fd_flags,
                        nonblock: false,
                    },
                );
                return fd as i64;
            }
        }
        // Paths not found in EmbeddedFs or device table → ENOENT.
        // Only fall through to the 9P backend when no EmbeddedFs is set.
        if efs_present {
            return ENOENT;
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

        // Cache file type at open time to avoid IPC on every lseek.
        let file_type = match self.backend.stat(fid) {
            Ok(s) => s.file_type,
            Err(_) => FileType::Regular, // best-effort default
        };

        let fd_flags = if flags & O_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };
        let fd = self.alloc_fd();
        self.fd_table.insert(
            fd,
            FdEntry {
                kind: FdKind::File {
                    fid,
                    offset: 0,
                    path: Some(path),
                    file_type,
                },
                flags: fd_flags,
                nonblock: is_nonblock,
            },
        );
        self.fid_refcount.insert(fid, 1);
        fd as i64
    }

    /// Linux exit(2): terminate the calling thread.
    ///
    /// In our single-threaded model, this is equivalent to exit_group.
    fn sys_exit(&mut self, code: i32) -> i64 {
        self.sys_exit_group(code)
    }

    /// Linux execve(2): replace process image with a new ELF binary.
    ///
    /// On success: closes FD_CLOEXEC fds, resets memory state, loads
    /// new ELF, builds initial stack, sets pending_execve for caller.
    /// On failure: returns negative errno, no state is modified.
    fn sys_execve(&mut self, path_ptr: u64, argv_ptr: u64, envp_ptr: u64) -> i64 {
        // NOTE: The full execve success path requires a VM-capable backend
        // because InterpreterLoader::load calls vm_mmap for segment mapping.
        // Arena-only backends fail at the ELF load step (vm_mmap returns
        // PageTableError). VM backends are blocked because they need
        // vm_reset_address_space (not yet implemented). A follow-up bead
        // will resolve this by either adding arena-based segment loading
        // or implementing vm_reset_address_space.
        //
        // Currently: VM backends → ENOSYS, arena backends → ENOEXEC at
        // the ELF load step. The apply_execve helper is fully functional
        // and tested via synthetic LoadResult.
        if self.backend.has_vm_support() {
            return ENOSYS;
        }

        if path_ptr == 0 {
            return EFAULT;
        }

        // Read path, argv, envp from user memory.
        let path = unsafe { read_c_string(path_ptr as usize) };
        let path = self.resolve_path(&path);
        let argv = read_string_array(argv_ptr, 256);
        let envp = read_string_array(envp_ptr, 256);

        // Fetch ELF bytes — prefer EmbeddedFs, fall back to 9P.
        let embedded_elf: Option<Vec<u8>> = if let Some(ref efs) = self.embedded_fs {
            if let Some(file) = efs.get(&path) {
                if !file.executable {
                    return EACCES;
                }
                if file.data.is_empty() {
                    return ENOEXEC;
                }
                Some(file.data.to_vec())
            } else {
                None // Not in EmbeddedFs — fall through to 9P
            }
        } else {
            None
        };

        let elf_bytes: Vec<u8> = if let Some(bytes) = embedded_elf {
            bytes
        } else {
            // Read ELF binary from 9P filesystem.
            let fid = self.alloc_fid();
            if let Err(e) = self.backend.walk(&path, fid) {
                return ipc_err_to_errno(e);
            }
            if let Err(e) = self.backend.open(fid, OpenMode::Read) {
                let _ = self.backend.clunk(fid);
                return ipc_err_to_errno(e);
            }

            let file_size = match self.backend.stat(fid) {
                Ok(stat) => stat.size,
                Err(e) => {
                    let _ = self.backend.clunk(fid);
                    return ipc_err_to_errno(e);
                }
            };

            const MAX_ELF_SIZE: u64 = 4 * 1024 * 1024; // 4 MiB
            if file_size > MAX_ELF_SIZE {
                let _ = self.backend.clunk(fid);
                return ENOMEM;
            }

            let bytes = match self.backend.read(fid, 0, file_size as u32) {
                Ok(b) => b,
                Err(e) => {
                    let _ = self.backend.clunk(fid);
                    return ipc_err_to_errno(e);
                }
            };
            let _ = self.backend.clunk(fid);
            bytes
        };

        // Load ELF via InterpreterLoader.
        let mut loader = InterpreterLoader::default();
        let load_result = match loader.load(&elf_bytes, &mut self.backend) {
            Ok(r) => r,
            Err(_) => return ENOEXEC,
        };

        // Verify arena is large enough for the stack before the point
        // of no return (close_cloexec_fds + reset_for_execve are irreversible).
        if self.arena_size < EXECVE_STACK_SIZE {
            return ENOMEM;
        }

        // Apply the execve (point of no return).
        self.apply_execve(&load_result, &argv, &envp);

        0 // success — caller checks pending_execve()
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
                Some(FdEntry {
                    kind: FdKind::File { fid, .. },
                    ..
                }) => Some(*fid),
                Some(_) => return ENODEV, // valid fd, but not a mappable type
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

    /// Linux rt_sigaction(2): register or query a signal handler.
    fn sys_rt_sigaction(
        &mut self,
        signum: i32,
        act_ptr: u64,
        oldact_ptr: u64,
        sigsetsize: u64,
    ) -> i64 {
        if sigsetsize != 8 {
            return EINVAL;
        }
        if !(1..=64).contains(&signum) {
            return EINVAL;
        }
        // SIGKILL/SIGSTOP: reject attempts to change the handler, but
        // allow read-only queries (act_ptr == 0). Linux: do_sigaction
        // checks `(act && sig_kernel_only(sig))`.
        if (signum == SIGKILL as i32 || signum == SIGSTOP as i32) && act_ptr != 0 {
            return EINVAL;
        }

        let idx = (signum - 1) as usize;

        // Read input BEFORE writing output (handles aliased pointers
        // where act_ptr == oldact_ptr).
        let new_action = if act_ptr != 0 {
            Some(Self::read_sigaction(act_ptr))
        } else {
            None
        };

        if oldact_ptr != 0 {
            let action = &self.signal_handlers[idx];
            Self::write_sigaction(oldact_ptr, action);
        }

        if let Some(action) = new_action {
            self.signal_handlers[idx] = action;
        }

        0
    }

    /// Read a kernel sigaction struct from user memory.
    fn read_sigaction(ptr: u64) -> SignalAction {
        let addr = ptr as usize;
        let handler = u64::from_ne_bytes(
            unsafe { core::slice::from_raw_parts(addr as *const u8, 8) }
                .try_into()
                .unwrap(),
        );
        let flags = u64::from_ne_bytes(
            unsafe { core::slice::from_raw_parts((addr + 8) as *const u8, 8) }
                .try_into()
                .unwrap(),
        );

        #[cfg(target_arch = "x86_64")]
        let restorer = u64::from_ne_bytes(
            unsafe { core::slice::from_raw_parts((addr + 16) as *const u8, 8) }
                .try_into()
                .unwrap(),
        );
        #[cfg(not(target_arch = "x86_64"))]
        let restorer = 0u64;

        #[cfg(target_arch = "x86_64")]
        let mask_offset = 24;
        #[cfg(not(target_arch = "x86_64"))]
        let mask_offset = 16;

        let mask = u64::from_ne_bytes(
            unsafe { core::slice::from_raw_parts((addr + mask_offset) as *const u8, 8) }
                .try_into()
                .unwrap(),
        );

        SignalAction {
            handler,
            mask,
            flags,
            restorer,
        }
    }

    /// Write a kernel sigaction struct to user memory.
    fn write_sigaction(ptr: u64, action: &SignalAction) {
        let addr = ptr as usize;
        unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, 8) }
            .copy_from_slice(&action.handler.to_ne_bytes());
        unsafe { core::slice::from_raw_parts_mut((addr + 8) as *mut u8, 8) }
            .copy_from_slice(&action.flags.to_ne_bytes());

        #[cfg(target_arch = "x86_64")]
        {
            // Write sa_restorer at offset 16.
            unsafe { core::slice::from_raw_parts_mut((addr + 16) as *mut u8, 8) }
                .copy_from_slice(&action.restorer.to_ne_bytes());
        }

        #[cfg(target_arch = "x86_64")]
        let mask_offset = 24;
        #[cfg(not(target_arch = "x86_64"))]
        let mask_offset = 16;

        unsafe { core::slice::from_raw_parts_mut((addr + mask_offset) as *mut u8, 8) }
            .copy_from_slice(&action.mask.to_ne_bytes());
    }

    /// Linux rt_sigprocmask(2): manage the blocked signal mask.
    fn sys_rt_sigprocmask(
        &mut self,
        how: i32,
        set_ptr: u64,
        oldset_ptr: u64,
        sigsetsize: u64,
    ) -> i64 {
        if sigsetsize != 8 {
            return EINVAL;
        }

        // Capture old mask and read input BEFORE writing output.
        // Handles aliased pointers (set_ptr == oldset_ptr) and ensures
        // oldset is only written after successful how validation
        // (matches Linux kernel ordering).
        let old_mask = self.signal_mask;

        if set_ptr != 0 {
            let set_bytes =
                unsafe { core::slice::from_raw_parts(set_ptr as usize as *const u8, 8) };
            let set = u64::from_ne_bytes(set_bytes.try_into().unwrap());

            match how {
                SIG_BLOCK => self.signal_mask |= set,
                SIG_UNBLOCK => self.signal_mask &= !set,
                SIG_SETMASK => self.signal_mask = set,
                _ => return EINVAL,
            }

            // SIGKILL (9) and SIGSTOP (19) can never be blocked.
            self.signal_mask &= !(1u64 << (SIGKILL - 1) | 1u64 << (SIGSTOP - 1));
        }

        // Write old mask only after successful operation.
        if oldset_ptr != 0 {
            let buf = unsafe { core::slice::from_raw_parts_mut(oldset_ptr as usize as *mut u8, 8) };
            buf.copy_from_slice(&old_mask.to_ne_bytes());
        }

        0
    }

    /// Linux rt_sigreturn(2): restore register state and signal mask
    /// from the signal frame on the user stack.
    ///
    /// Frame layout from handler_rsp:
    ///   +0:   retaddr (consumed by ret)
    ///   +8:   ucontext_t (304 bytes)
    ///         ├─ uc_flags/uc_link/uc_stack  (40 bytes)
    ///         ├─ sigcontext (32 u64 × 8)   (256 bytes)
    ///         └─ uc_sigmask                  (8 bytes)
    ///   +312: siginfo_t (128 bytes)
    ///
    /// RSP passed to us = handler_rsp + 8 (retaddr already popped).
    /// ucontext at rsp, siginfo at rsp + 304.
    fn sys_rt_sigreturn(&mut self, rsp: u64) -> i64 {
        let ucontext_ptr = rsp as usize; // ucontext is right after retaddr (which was popped)
        let sc = ucontext_ptr + 40; // sigcontext within ucontext

        let regs = unsafe {
            SavedRegisters {
                r8: core::ptr::read_unaligned(sc as *const u64),
                r9: core::ptr::read_unaligned((sc + 8) as *const u64),
                r10: core::ptr::read_unaligned((sc + 16) as *const u64),
                r11: core::ptr::read_unaligned((sc + 24) as *const u64),
                r12: core::ptr::read_unaligned((sc + 32) as *const u64),
                r13: core::ptr::read_unaligned((sc + 40) as *const u64),
                r14: core::ptr::read_unaligned((sc + 48) as *const u64),
                r15: core::ptr::read_unaligned((sc + 56) as *const u64),
                rdi: core::ptr::read_unaligned((sc + 64) as *const u64),
                rsi: core::ptr::read_unaligned((sc + 72) as *const u64),
                rbp: core::ptr::read_unaligned((sc + 80) as *const u64),
                rbx: core::ptr::read_unaligned((sc + 88) as *const u64),
                rdx: core::ptr::read_unaligned((sc + 96) as *const u64),
                rax: core::ptr::read_unaligned((sc + 104) as *const u64),
                rcx: core::ptr::read_unaligned((sc + 112) as *const u64),
                rsp: core::ptr::read_unaligned((sc + 120) as *const u64),
                rip: core::ptr::read_unaligned((sc + 128) as *const u64),
                eflags: core::ptr::read_unaligned((sc + 136) as *const u64),
            }
        };

        // Restore signal mask from uc_sigmask (at ucontext + 296).
        let uc_sigmask = unsafe { core::ptr::read_unaligned((ucontext_ptr + 296) as *const u64) };
        self.signal_mask = uc_sigmask;
        self.signal_mask &= !(1u64 << (SIGKILL - 1) | 1u64 << (SIGSTOP - 1));

        // Restore on_alt_stack from the frame's saved uc_stack.ss_flags.
        // This handles nested signals correctly: if the interrupted context
        // was already on the alt stack (SS_ONSTACK set in saved flags),
        // we stay on it; otherwise we clear it.
        let saved_ss_flags =
            unsafe { core::ptr::read_unaligned((ucontext_ptr + 24) as *const i32) };
        self.on_alt_stack = saved_ss_flags & SS_ONSTACK != 0;

        self.pending_signal_return = Some(SignalReturn { regs });

        // Return value is meaningless — caller uses pending_signal_return().
        regs.rax as i64
    }

    /// Linux sigaltstack(2): get/set alternate signal stack configuration.
    fn sys_sigaltstack(&mut self, ss_ptr: u64, old_ss_ptr: u64) -> i64 {
        // Snapshot current config before any mutation (Linux writes old_ss
        // only on success — never dirty the caller's buffer on error).
        let old_sp = self.alt_stack_sp;
        let old_flags = self.alt_stack_flags | if self.on_alt_stack { SS_ONSTACK } else { 0 };
        let old_size = self.alt_stack_size;

        // Validate and apply new config first.
        if ss_ptr != 0 {
            if self.on_alt_stack {
                return EPERM;
            }
            let (sp, flags, size) = unsafe {
                let p = ss_ptr as usize;
                let sp = core::ptr::read_unaligned(p as *const u64);
                let flags = core::ptr::read_unaligned((p + 8) as *const i32);
                let size = core::ptr::read_unaligned((p + 16) as *const u64);
                (sp, flags, size)
            };

            if flags & !SS_DISABLE != 0 {
                return EINVAL;
            }

            if flags & SS_DISABLE != 0 {
                self.alt_stack_sp = 0;
                self.alt_stack_size = 0;
                self.alt_stack_flags = SS_DISABLE;
            } else {
                if size < MINSIGSTKSZ {
                    return ENOMEM;
                }
                self.alt_stack_sp = sp;
                self.alt_stack_size = size;
                self.alt_stack_flags = flags;
            }
        }

        // Write old state only after successful validation.
        if old_ss_ptr != 0 {
            unsafe {
                let p = old_ss_ptr as usize;
                core::ptr::write_unaligned(p as *mut u64, old_sp);
                core::ptr::write_unaligned((p + 8) as *mut i32, old_flags);
                core::ptr::write_unaligned((p + 16) as *mut u64, old_size);
            }
        }

        0
    }

    /// Linux set_tid_address(2): return TID = 1 (single-threaded).
    fn sys_set_tid_address(&self) -> i64 {
        self.pid as i64
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
        if iov_ptr == 0 {
            return EFAULT;
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
            if (result as usize) < len {
                break; // short write — stop, matching POSIX writev semantics
            }
        }
        total
    }

    /// Linux readv(2): scatter read — read into multiple buffers.
    ///
    /// Mirrors `sys_writev`: iterates `iovcnt` iovec structs at `iov_ptr`,
    /// calling `sys_read` for each non-zero buffer and accumulating the total
    /// bytes read. On the first error, returns that error if nothing has been
    /// read yet, otherwise returns the partial total (POSIX partial read).
    fn sys_readv(&mut self, fd: i32, iov_ptr: usize, iovcnt: i32) -> i64 {
        const IOV_MAX: i32 = 1024;
        if iovcnt == 0 {
            return 0;
        }
        if !(1..=IOV_MAX).contains(&iovcnt) {
            return EINVAL;
        }
        if iov_ptr == 0 {
            return EFAULT;
        }
        if !self.fd_table.contains_key(&fd) {
            return EBADF;
        }

        let mut total: i64 = 0;
        for i in 0..iovcnt as usize {
            let iov_addr = iov_ptr + i * 16;
            let base = unsafe { core::ptr::read_unaligned(iov_addr as *const u64) } as usize;
            let len = unsafe { core::ptr::read_unaligned((iov_addr + 8) as *const u64) } as usize;

            if len == 0 {
                continue;
            }
            let result = self.sys_read(fd, base, len);
            if result < 0 {
                return if total == 0 { result } else { total };
            }
            total = total.saturating_add(result);
            if (result as usize) < len {
                break; // short read — stop, matching Linux readv semantics
            }
        }
        total
    }

    /// Linux socketpair(2): create a pair of connected socket stubs.
    ///
    /// Creates two socket fds backed by the same `SocketState`. Only
    /// `AF_UNIX` (domain 1) is accepted. `SOCK_CLOEXEC` / `SOCK_NONBLOCK`
    /// flags are honoured. Writes the two fds as `[i32; 2]` to `sv`.
    fn sys_socketpair(&mut self, domain: i32, sock_type: i32, _protocol: i32, sv: u64) -> i64 {
        const AF_UNIX: i32 = 1;
        const SOCK_CLOEXEC: i32 = 0o2000000;
        const SOCK_NONBLOCK: i32 = 0o4000;

        if domain != AF_UNIX {
            return EAFNOSUPPORT;
        }
        if sv == 0 {
            return EFAULT;
        }

        let flags = sock_type & (SOCK_CLOEXEC | SOCK_NONBLOCK);
        let base_type = sock_type & !(SOCK_CLOEXEC | SOCK_NONBLOCK);
        let fd_flags = if flags & SOCK_CLOEXEC != 0 {
            FD_CLOEXEC
        } else {
            0
        };

        // Both ends share a single SocketState (same socket_id).
        // socketpair is AF_UNIX only; no TCP handle needed.
        let socket_id = self.next_socket_id;
        self.next_socket_id += 1;
        let is_nonblock = flags & SOCK_NONBLOCK != 0;
        self.sockets.insert(
            socket_id,
            SocketState {
                domain,
                sock_type: base_type,
                listening: false,
                accepted_once: false,
                tcp_handle: None,
                udp_handle: None,
                bound_port: 0,
            },
        );

        let fd0 = self.alloc_fd();
        self.fd_table.insert(
            fd0,
            FdEntry {
                kind: FdKind::Socket { socket_id },
                flags: fd_flags,
                nonblock: is_nonblock,
            },
        );
        let fd1 = self.alloc_fd();
        self.fd_table.insert(
            fd1,
            FdEntry {
                kind: FdKind::Socket { socket_id },
                flags: fd_flags,
                nonblock: is_nonblock,
            },
        );

        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&fd0.to_le_bytes());
        buf[4..8].copy_from_slice(&fd1.to_le_bytes());
        self.backend.vm_write_bytes(sv, &buf);

        0
    }

    /// Linux getrlimit(2): query resource limit.
    ///
    /// Consistent with prlimit64: RLIMIT_STACK (3) returns 8 MiB,
    /// all other resources return RLIM_INFINITY.
    fn sys_getrlimit(&mut self, resource: i32, rlim_ptr: usize) -> i64 {
        if rlim_ptr == 0 {
            return EFAULT;
        }
        const RLIMIT_STACK: i32 = 3;
        const STACK_SIZE: u64 = 8 * 1024 * 1024; // 8 MiB, matches prlimit64
        let (cur, max) = if resource == RLIMIT_STACK {
            (STACK_SIZE, STACK_SIZE)
        } else {
            (u64::MAX, u64::MAX)
        };
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&cur.to_le_bytes());
        buf[8..16].copy_from_slice(&max.to_le_bytes());
        self.backend.vm_write_bytes(rlim_ptr as u64, &buf);
        0
    }

    /// Linux setrlimit(2): set resource limit — stub, always succeeds.
    ///
    /// We do not enforce resource limits; accept and ignore the request.
    fn sys_setrlimit(&self) -> i64 {
        0
    }

    /// Linux umask(2): set file creation mask.
    ///
    /// Stores the new mask and returns the old mask.
    fn sys_umask(&mut self, mask: u32) -> i64 {
        let old = self.umask_val;
        self.umask_val = mask & 0o777; // S_IRWXUGO: 9 permission bits only
        old as i64
    }

    /// Linux ftruncate(2): truncate a file to a specified length — stub.
    ///
    /// Validates that `fd` is an open regular file fd. Returns 0 (stub
    /// success) — our files are read-only or 9P-backed; truncation is not
    /// implemented, but returning 0 avoids breaking programs that probe.
    fn sys_ftruncate(&self, fd: i32) -> i64 {
        match self.fd_table.get(&fd) {
            Some(FdEntry {
                kind: FdKind::File { file_type, .. },
                ..
            }) => {
                if *file_type == FileType::CharDev || *file_type == FileType::Directory {
                    EINVAL
                } else {
                    0
                }
            }
            Some(_) => EINVAL,
            None => EBADF,
        }
    }

    /// Linux renameat(2): rename a file relative to directory fds.
    ///
    /// Supports renaming scratch files in the EmbeddedFs overlay.
    /// Returns EROFS for static embedded files.
    fn sys_renameat(
        &mut self,
        _olddirfd: i32,
        oldpath_ptr: u64,
        _newdirfd: i32,
        newpath_ptr: u64,
    ) -> i64 {
        if oldpath_ptr == 0 || newpath_ptr == 0 {
            return EFAULT;
        }
        let old_raw = unsafe { read_c_string(oldpath_ptr as usize) };
        let new_raw = unsafe { read_c_string(newpath_ptr as usize) };
        let old_path = self.resolve_path(&old_raw);
        let new_path = self.resolve_path(&new_raw);

        if let Some(ref mut efs) = self.embedded_fs {
            if efs.rename_scratch(&old_path, &new_path) {
                return 0;
            }
        }
        EROFS
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

        // Handle EmbeddedFile lseek — these are seekable regular files.
        if let Some(FdEntry {
            kind:
                FdKind::EmbeddedFile {
                    ref path,
                    offset: cur_offset,
                },
            ..
        }) = self.fd_table.get(&fd)
        {
            let file_size = self
                .embedded_fs
                .as_ref()
                .and_then(|efs| efs.get(path))
                .map(|f| f.data.len() as i64)
                .unwrap_or(0);
            let cur = *cur_offset as i64;
            let new_offset = match whence {
                SEEK_SET => offset,
                SEEK_CUR => match cur.checked_add(offset) {
                    Some(v) => v,
                    None => return EOVERFLOW,
                },
                SEEK_END => match file_size.checked_add(offset) {
                    Some(v) => v,
                    None => return EOVERFLOW,
                },
                _ => return EINVAL,
            };
            if new_offset < 0 {
                return EINVAL;
            }
            // Update offset — need to re-borrow mutably.
            if let Some(FdEntry {
                kind:
                    FdKind::EmbeddedFile {
                        offset: ref mut off,
                        ..
                    },
                ..
            }) = self.fd_table.get_mut(&fd)
            {
                *off = new_offset as u64;
            }
            return new_offset;
        }

        // Handle ScratchFile lseek.
        if let Some(FdEntry {
            kind:
                FdKind::ScratchFile {
                    ref path,
                    offset: cur_offset,
                },
            ..
        }) = self.fd_table.get(&fd)
        {
            let file_size = self
                .embedded_fs
                .as_ref()
                .and_then(|efs| efs.scratch.get(path))
                .map(|d| d.len() as i64)
                .unwrap_or(0);
            let cur = *cur_offset as i64;
            let new_offset = match whence {
                SEEK_SET => offset,
                SEEK_CUR => match cur.checked_add(offset) {
                    Some(v) => v,
                    None => return EOVERFLOW,
                },
                SEEK_END => match file_size.checked_add(offset) {
                    Some(v) => v,
                    None => return EOVERFLOW,
                },
                _ => return EINVAL,
            };
            if new_offset < 0 {
                return EINVAL;
            }
            if let Some(FdEntry {
                kind:
                    FdKind::ScratchFile {
                        offset: ref mut off,
                        ..
                    },
                ..
            }) = self.fd_table.get_mut(&fd)
            {
                *off = new_offset as u64;
            }
            return new_offset;
        }

        let (entry_fid, entry_offset, entry_file_type) = match self.fd_table.get(&fd) {
            Some(FdEntry {
                kind:
                    FdKind::File {
                        fid,
                        offset,
                        file_type,
                        ..
                    },
                ..
            }) => (*fid, *offset, *file_type),
            Some(_) => return ESPIPE,
            None => return EBADF,
        };

        // Character devices (stdin/stdout/stderr) are not seekable.
        // Uses cached file_type from FdEntry — no IPC needed.
        if entry_file_type == FileType::CharDev {
            return ESPIPE;
        }

        let new_offset = match whence {
            SEEK_SET => offset,
            SEEK_CUR => match (entry_offset as i64).checked_add(offset) {
                Some(v) => v,
                None => return EOVERFLOW,
            },
            SEEK_END => {
                // SEEK_END needs the current file size — stat required.
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

        if let FdKind::File { ref mut offset, .. } = self.fd_table.get_mut(&fd).unwrap().kind {
            *offset = new_offset as u64;
        }
        new_offset
    }

    /// Linux getrandom(2): fill buffer with pseudo-random bytes.
    ///
    /// Uses a deterministic LCG seeded from the buffer address and a
    /// monotonic call counter so that repeated calls to the same address
    /// produce distinct output.  This is sufficient for ld-musl stack
    /// canaries and ASLR seeds in the Linuxulator environment (no real
    /// security boundary).
    /// Fill a buffer with pseudo-random bytes (LCG-based).
    ///
    /// `extra_seed` is mixed into the initial state for caller-specific
    /// diversity (e.g. the destination buffer address for getrandom).
    fn fill_random(&mut self, buf: &mut [u8], extra_seed: u64) {
        let counter = self.getrandom_counter;
        self.getrandom_counter = counter.wrapping_add(1);
        let mut state = counter
            .wrapping_add(extra_seed)
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        for byte in buf.iter_mut() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (state >> 33) as u8;
        }
    }

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
        // Seed once, then maintain a single continuous LCG state across
        // all chunks (reseeding per chunk would produce correlated output).
        let counter = self.getrandom_counter;
        self.getrandom_counter = counter.wrapping_add(1);
        let mut state = (buf_ptr as u64)
            .wrapping_add(counter)
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
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

    /// Stat an fd or the cwd (when dirfd == AT_FDCWD).
    /// Used by `sys_newfstatat` for the AT_EMPTY_PATH cases.
    fn sys_stat_fd_or_cwd(&mut self, dirfd: i32, statbuf_ptr: usize) -> i64 {
        const AT_FDCWD: i32 = -100;
        if dirfd == AT_FDCWD {
            let cwd = self.cwd.clone();
            // Note: alloc_fid() advances the monotonic counter even if walk
            // fails. This is acceptable — the u32 counter won't wrap in
            // practice, and clunking a never-walked fid is a 9P violation.
            let fid = self.alloc_fid();
            if let Err(e) = self.backend.walk(&cwd, fid) {
                return ipc_err_to_errno(e);
            }
            let result = match self.backend.stat(fid) {
                Ok(stat) => {
                    write_linux_stat(statbuf_ptr, &stat);
                    0
                }
                Err(e) => ipc_err_to_errno(e),
            };
            let _ = self.backend.clunk(fid);
            result
        } else {
            self.sys_fstat(dirfd, statbuf_ptr)
        }
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

        // Handle null/empty pathname for AT_EMPTY_PATH, or return EFAULT/ENOENT.
        if pathname_ptr == 0 {
            if flags & AT_EMPTY_PATH != 0 {
                return self.sys_stat_fd_or_cwd(dirfd, statbuf_ptr);
            }
            return EFAULT;
        }
        let path = unsafe { read_c_string(pathname_ptr) };
        if path.is_empty() {
            if flags & AT_EMPTY_PATH != 0 {
                return self.sys_stat_fd_or_cwd(dirfd, statbuf_ptr);
            }
            return ENOENT;
        }

        let resolved = if dirfd == AT_FDCWD || path.starts_with('/') {
            self.resolve_path(&path)
        } else if self.fd_table.contains_key(&dirfd) {
            // dirfd-relative paths: not yet supported
            return ENOSYS;
        } else {
            return EBADF;
        };

        // Check EmbeddedFs before issuing a 9P walk.
        if let Some(ref efs) = self.embedded_fs {
            // Check scratch files first (may shadow static files).
            if let Some(data) = efs.scratch.get(&resolved) {
                let stat = FileStat {
                    qpath: 0,
                    name: alloc::sync::Arc::from(resolved.as_str()),
                    size: data.len() as u64,
                    file_type: FileType::Regular,
                };
                write_linux_stat_with_mode(statbuf_ptr, &stat, Some(0o100644));
                return 0;
            }
            if let Some(file) = efs.get(&resolved) {
                let mode: u32 = if file.executable { 0o100755 } else { 0o100644 };
                let size = file.data.len() as u64;
                let stat = FileStat {
                    qpath: 0,
                    name: alloc::sync::Arc::from(resolved.as_str()),
                    size,
                    file_type: FileType::Regular,
                };
                write_linux_stat_with_mode(statbuf_ptr, &stat, Some(mode));
                return 0;
            } else if efs.exists(&resolved) {
                // Directory entry derived from embedded files.
                // .ssh directories need mode 0700 (dropbear rejects group/other access).
                let dir_mode: u32 = if resolved.ends_with("/.ssh") {
                    0o040700
                } else {
                    0o040755
                };
                let stat = FileStat {
                    qpath: 0,
                    name: alloc::sync::Arc::from(resolved.as_str()),
                    size: 0,
                    file_type: FileType::Directory,
                };
                write_linux_stat_with_mode(statbuf_ptr, &stat, Some(dir_mode));
                return 0;
            }
        }

        let fid = self.alloc_fid();
        if let Err(e) = self.backend.walk(&resolved, fid) {
            return ipc_err_to_errno(e);
        }
        let result = match self.backend.stat(fid) {
            Ok(stat) => {
                write_linux_stat(statbuf_ptr, &stat);
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
    /// pass (single-user, no capability enforcement yet). Note: `W_OK`
    /// succeeds even though the filesystem is read-only; callers that use
    /// `faccessat(W_OK)` for writability detection will be misled.
    fn sys_faccessat(&mut self, dirfd: i32, pathname_ptr: usize, _mode: i32) -> i64 {
        if pathname_ptr == 0 {
            return EFAULT;
        }
        const AT_FDCWD: i32 = -100;
        let path = unsafe { read_c_string(pathname_ptr) };
        if path.is_empty() {
            return ENOENT;
        }

        let resolved = if dirfd == AT_FDCWD || path.starts_with('/') {
            self.resolve_path(&path)
        } else if self.fd_table.contains_key(&dirfd) {
            // dirfd-relative paths: not yet supported
            return ENOSYS;
        } else {
            return EBADF;
        };

        // Check EmbeddedFs before issuing a 9P walk.
        let efs_exists = self
            .embedded_fs
            .as_ref()
            .is_some_and(|efs| efs.exists(&resolved));
        if efs_exists {
            return 0;
        }

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
        let (dir_fid, start_idx) = match self.fd_table.get(&fd) {
            Some(FdEntry {
                kind: FdKind::File { fid, offset, .. },
                ..
            }) => (*fid, *offset as usize),
            Some(_) => return ENOTDIR,
            None => return EBADF,
        };

        let entries = match self.backend.readdir(dir_fid) {
            Ok(e) => e,
            Err(e) => return ipc_err_to_errno(e),
        };

        if start_idx >= entries.len() {
            return 0; // End of directory
        }

        // Cap the kernel-side allocation to avoid OOM from user-controlled count.
        // 256 KiB matches a common glibc getdents64 buffer size.
        const GETDENTS_BUF_MAX: usize = 256 * 1024;
        let capped_count = count.min(GETDENTS_BUF_MAX);
        let mut buf = vec![0u8; capped_count];
        let mut bytes_written: usize = 0;
        let mut idx = start_idx;

        while idx < entries.len() {
            let e = &entries[idx];
            let name_bytes = e.name.as_bytes();
            // d_ino(8) + d_off(8) + d_reclen(2) + d_type(1) + name + NUL
            let reclen_unaligned = 8 + 8 + 2 + 1 + name_bytes.len() + 1;
            let reclen = (reclen_unaligned + 7) & !7; // 8-byte align

            // Guard against filenames exceeding d_reclen's u16 range.
            if reclen > u16::MAX as usize {
                return EINVAL;
            }

            if bytes_written + reclen > capped_count {
                break; // Buffer full
            }

            let d_type: u8 = match e.file_type {
                FileType::Regular => 8,   // DT_REG
                FileType::Directory => 4, // DT_DIR
                FileType::CharDev => 2,   // DT_CHR
            };

            // Pack the entry into the pre-allocated buffer.
            let rec = &mut buf[bytes_written..bytes_written + reclen];
            // rec is already zeroed (NUL terminator included)
            let d_ino = (idx + 1) as u64; // non-zero placeholder; 0 means "deleted"
            rec[0..8].copy_from_slice(&d_ino.to_le_bytes()); // d_ino

            // d_off: entry index used as seek position (Linuxulator-internal
            // convention — not a byte offset, but consistent with how
            // FdEntry.offset tracks pagination via lseek).
            let next_off = (idx + 1) as i64;
            rec[8..16].copy_from_slice(&next_off.to_le_bytes()); // d_off
            rec[16..18].copy_from_slice(&(reclen as u16).to_le_bytes()); // d_reclen
            rec[18] = d_type; // d_type
            rec[19..19 + name_bytes.len()].copy_from_slice(name_bytes); // d_name

            bytes_written += reclen;
            idx += 1;
        }

        // Single write for all packed entries.
        if bytes_written > 0 {
            self.backend
                .vm_write_bytes(dirp as u64, &buf[..bytes_written]);
        }

        if bytes_written == 0 && idx < entries.len() {
            return EINVAL; // Buffer too small for even one entry
        }

        // Update the offset to track position.
        if let Some(entry) = self.fd_table.get_mut(&fd) {
            if let FdKind::File { ref mut offset, .. } = entry.kind {
                *offset = idx as u64;
            }
        }

        bytes_written as i64
    }

    /// Linux chdir(2): change working directory.
    ///
    /// Walks the path, verifies it's a directory via stat, then
    /// updates `self.cwd`. The walked fid is transient — clunked
    /// immediately after verification.
    fn sys_chdir(&mut self, pathname_ptr: usize) -> i64 {
        if pathname_ptr == 0 {
            return EFAULT;
        }
        let path = unsafe { read_c_string(pathname_ptr) };
        if path.is_empty() {
            return ENOENT;
        }
        let resolved = self.resolve_path(&path);

        // Check EmbeddedFs for the directory before falling through to 9P.
        if let Some(ref efs) = self.embedded_fs {
            if efs.exists(&resolved) && efs.get(&resolved).is_none() {
                // Path exists as a directory (not a file) in EmbeddedFs.
                self.cwd = resolved;
                return 0;
            }
            if efs.get(&resolved).is_some() {
                return -20; // ENOTDIR
            }
            // Not in EmbeddedFs at all — still try 9P below.
        }

        let fid = self.alloc_fid();
        if let Err(e) = self.backend.walk(&resolved, fid) {
            return ipc_err_to_errno(e);
        }

        // Verify it's a directory, then clunk the transient fid
        let result = match self.backend.stat(fid) {
            Ok(stat) if stat.file_type == FileType::Directory => {
                self.cwd = resolved;
                0
            }
            Ok(_) => ENOTDIR,
            Err(e) => ipc_err_to_errno(e),
        };
        let _ = self.backend.clunk(fid);
        result
    }

    /// Linux fchdir(2): change working directory to an open fd.
    fn sys_fchdir(&mut self, fd: i32) -> i64 {
        let (fid, path) = match self.fd_table.get(&fd) {
            Some(FdEntry {
                kind: FdKind::File { fid, path, .. },
                ..
            }) => (*fid, path.clone()),
            Some(_) => return ENOTDIR,
            None => return EBADF,
        };

        // Verify it's a directory before checking path — a valid non-directory
        // fd (e.g. stdio) should return ENOTDIR, not EBADF.
        match self.backend.stat(fid) {
            Ok(stat) if stat.file_type == FileType::Directory => {}
            Ok(_) => return ENOTDIR,
            Err(e) => return ipc_err_to_errno(e),
        }

        let path = match &path {
            Some(p) => p.clone(),
            None => {
                // fd is confirmed directory but has no tracked path —
                // implementation limitation. All current directory fds have
                // paths, so this is effectively unreachable.
                debug_assert!(false, "directory fd {} has no tracked path", fd);
                return EINVAL;
            }
        };

        self.cwd = path;
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

    /// Linux getpid(2): return process ID.
    fn sys_getpid(&self) -> i64 {
        self.pid as i64
    }

    /// Linux getppid(2): return parent process ID.
    fn sys_getppid(&self) -> i64 {
        self.parent_pid as i64
    }

    /// Linux gettid(2): return thread ID.
    ///
    /// Single-threaded model — TID matches PID.
    fn sys_gettid(&self) -> i64 {
        self.pid as i64
    }

    /// Linux getuid(2): return real user ID.
    ///
    /// Single-user system running as root — returns 0.
    fn sys_getuid(&self) -> i64 {
        0
    }

    /// Linux geteuid(2): return effective user ID.
    ///
    /// Single-user system running as root — returns 0.
    fn sys_geteuid(&self) -> i64 {
        0
    }

    /// Linux getgid(2): return real group ID.
    ///
    /// Single-user system running as root — returns 0.
    fn sys_getgid(&self) -> i64 {
        0
    }

    /// Linux getegid(2): return effective group ID.
    ///
    /// Single-user system running as root — returns 0.
    fn sys_getegid(&self) -> i64 {
        0
    }

    /// Linux madvise(2): advise kernel about memory usage.
    ///
    /// Advisory only — always succeeds.
    fn sys_madvise(&self) -> i64 {
        0
    }

    /// Linux futex(2): fast userspace locking.
    ///
    /// FUTEX_WAKE (cmd 1): returns 0 (no waiters — single-threaded).
    /// FUTEX_WAIT (cmd 0): returns EAGAIN (can't block in single-threaded model).
    /// All other operations return ENOSYS.
    fn sys_futex(&self, uaddr: u64, op: i32, val: u32) -> i64 {
        // The op field's lower bits encode the command; upper bits are
        // flags (FUTEX_PRIVATE_FLAG, etc.).  Mask to the command bits.
        const FUTEX_CMD_MASK: i32 = 0x7f;
        const FUTEX_WAIT: i32 = 0;
        const FUTEX_WAKE: i32 = 1;
        match op & FUTEX_CMD_MASK {
            FUTEX_WAKE => 0, // no waiters in single-threaded model
            FUTEX_WAIT => {
                // In single-threaded model, FUTEX_WAIT checks *uaddr == val.
                // If equal, would block (but we can't block) → EAGAIN.
                // If not equal, return EAGAIN (value changed).
                // Either way, return EAGAIN — there's no other thread to
                // wake us up, so blocking would deadlock.
                if uaddr == 0 {
                    return EFAULT;
                }
                let current = unsafe { *(uaddr as usize as *const u32) };
                if current != val {
                    return EAGAIN; // value changed
                }
                // Value matches — would block, but single-threaded → EAGAIN
                EAGAIN
            }
            _ => ENOSYS,
        }
    }

    /// Linux poll(2): synchronous I/O multiplexing via pollfd array.
    ///
    /// Yields to the scheduler until at least one fd is ready or the timeout expires.
    fn sys_poll(&mut self, fds_ptr: u64, nfds: u64, timeout_ms: i32) -> i64 {
        const POLL_MAX_FDS: u64 = 1 << 20;
        if nfds > POLL_MAX_FDS {
            return EINVAL;
        }
        if fds_ptr == 0 && nfds > 0 {
            return EFAULT;
        }

        // Non-blocking: check once and return immediately.
        if timeout_ms == 0 {
            return self.poll_check_once(fds_ptr, nfds);
        }

        // Without poll_fn there is no way to read time — fall back to a
        // single check so the caller at least gets the current state.
        if self.poll_fn.is_none() {
            return self.poll_check_once(fds_ptr, nfds);
        }

        // Blocking path: check readiness first, then yield if not ready.
        if self.block_fn.is_some() {
            // Initial check — return immediately if fds are already ready.
            let ready = self.poll_check_once(fds_ptr, nfds);
            if ready > 0 {
                return ready;
            }

            let start_ms = self.poll_fn.map_or(0, |pf| pf());
            let deadline = if timeout_ms > 0 {
                start_ms.saturating_add(timeout_ms as u64)
            } else {
                u64::MAX // Negative timeout = infinite wait
            };

            loop {
                match self.block_until(BLOCK_OP_POLL, -1) {
                    BlockResult::Ready => {
                        let ready = self.poll_check_once(fds_ptr, nfds);
                        if ready > 0 {
                            return ready;
                        }
                        // Check timeout.
                        if timeout_ms > 0 {
                            let now = self.poll_fn.map_or(deadline, |pf| pf());
                            if now >= deadline {
                                return 0;
                            }
                        }
                        // No fds ready, timeout not expired — re-block.
                    }
                    BlockResult::Interrupted => return 0,
                }
            }
        } else {
            // No scheduler — do one check and return.
            self.poll_check_once(fds_ptr, nfds)
        }
    }

    /// Single-pass readiness check for poll(). Writes revents and returns ready count.
    fn poll_check_once(&self, fds_ptr: u64, nfds: u64) -> i64 {
        const POLLIN: i16 = 0x01;
        const POLLOUT: i16 = 0x04;
        const POLLHUP: i16 = 0x10;
        const POLLNVAL: i16 = 0x20;

        let mut ready_count = 0i64;
        for i in 0..nfds {
            let base = fds_ptr as usize + (i as usize) * 8;
            let fd_bytes = unsafe { core::slice::from_raw_parts(base as *const u8, 4) };
            let fd = i32::from_ne_bytes(fd_bytes.try_into().unwrap());
            let events_bytes = unsafe { core::slice::from_raw_parts((base + 4) as *const u8, 2) };
            let events = i16::from_ne_bytes(events_bytes.try_into().unwrap());

            let revents = if fd < 0 {
                0i16
            } else if !self.fd_table.contains_key(&fd) {
                POLLNVAL
            } else {
                let mut r = 0i16;
                if events & POLLIN != 0 && self.is_fd_readable(fd) {
                    r |= POLLIN;
                }
                if events & POLLOUT != 0 && self.is_fd_writable(fd) {
                    r |= POLLOUT;
                }
                // Check for HUP on sockets (connection closed).
                if let Some(entry) = self.fd_table.get(&fd) {
                    if let FdKind::Socket { socket_id } = &entry.kind {
                        if let Some(state) = self.sockets.get(socket_id) {
                            if let Some(h) = state.tcp_handle {
                                let tcp_state = self.tcp.tcp_state(h);
                                if tcp_state == TcpSocketState::Closed
                                    || tcp_state == TcpSocketState::Closing
                                {
                                    r |= POLLHUP;
                                }
                            }
                        }
                    }
                }
                r
            };

            if revents != 0 {
                ready_count += 1;
            }
            let revents_out = unsafe { core::slice::from_raw_parts_mut((base + 6) as *mut u8, 2) };
            revents_out.copy_from_slice(&revents.to_ne_bytes());
        }
        ready_count
    }

    /// Linux ppoll(2): like poll but with timespec and signal mask.
    fn sys_ppoll(&mut self, fds_ptr: u64, nfds: u64, timeout_ptr: u64, _sigmask: u64) -> i64 {
        let timeout_ms: i32 = if timeout_ptr == 0 {
            -1 // NULL → block forever
        } else {
            let ts = unsafe { core::slice::from_raw_parts(timeout_ptr as *const u8, 16) };
            let tv_sec = i64::from_ne_bytes(ts[0..8].try_into().unwrap());
            let tv_nsec = i64::from_ne_bytes(ts[8..16].try_into().unwrap());
            if tv_sec < 0 || !(0..1_000_000_000).contains(&tv_nsec) {
                return EINVAL;
            }
            let ms = tv_sec
                .saturating_mul(1000)
                .saturating_add((tv_nsec + 999_999) / 1_000_000);
            ms.min(i32::MAX as i64) as i32
        };
        self.sys_poll(fds_ptr, nfds, timeout_ms)
    }

    /// Linux select(2): synchronous I/O multiplexing via fd_set bitmasks.
    ///
    /// Yields to the scheduler until at least one fd is ready or the timeout expires.
    fn sys_select(
        &mut self,
        nfds: i32,
        readfds: u64,
        writefds: u64,
        exceptfds: u64,
        timeout_ptr: u64,
    ) -> i64 {
        if !(0..=1024).contains(&nfds) {
            return EINVAL;
        }

        // Parse struct timeval { tv_sec: i64, tv_usec: i64 }.
        // Parse once, then handle non-blocking / blocking paths.
        let timeout_ms: u64 = if timeout_ptr == 0 {
            u64::MAX // NULL → block forever (sentinel)
        } else {
            let tv = unsafe { core::slice::from_raw_parts(timeout_ptr as *const u8, 16) };
            let tv_sec = i64::from_ne_bytes(tv[0..8].try_into().unwrap());
            let tv_usec = i64::from_ne_bytes(tv[8..16].try_into().unwrap());
            if tv_sec < 0 || tv_usec < 0 {
                return EINVAL;
            }
            // Linux normalizes out-of-range tv_usec (e.g. 2_500_000 = 2.5s extra).
            (tv_sec as u64)
                .saturating_mul(1000)
                .saturating_add((tv_usec as u64).div_ceil(1000))
        };

        // {0,0} → non-blocking: check once and return.
        if timeout_ms == 0 {
            return self.select_check_once(nfds, readfds, writefds, exceptfds);
        }

        // Without poll_fn there is no way to read time — fall back to a
        // single check so the caller at least gets the current state.
        if self.poll_fn.is_none() {
            return self.select_check_once(nfds, readfds, writefds, exceptfds);
        }

        // Save copies of the input fd_sets (select overwrites them with results).
        let read_bytes = (nfds as usize).div_ceil(8);
        let mut saved_readfds = [0u8; 128];
        let mut saved_writefds = [0u8; 128];
        let mut saved_exceptfds = [0u8; 128];
        if readfds != 0 && read_bytes > 0 {
            let src = unsafe { core::slice::from_raw_parts(readfds as *const u8, read_bytes) };
            saved_readfds[..read_bytes].copy_from_slice(src);
        }
        if writefds != 0 && read_bytes > 0 {
            let src = unsafe { core::slice::from_raw_parts(writefds as *const u8, read_bytes) };
            saved_writefds[..read_bytes].copy_from_slice(src);
        }
        if exceptfds != 0 && read_bytes > 0 {
            let src = unsafe { core::slice::from_raw_parts(exceptfds as *const u8, read_bytes) };
            saved_exceptfds[..read_bytes].copy_from_slice(src);
        }

        // Helper closure to clear all fd_sets (Linux convention on timeout/interrupt).
        let clear_fdsets = |readfds: u64, writefds: u64, exceptfds: u64, read_bytes: usize| {
            if readfds != 0 {
                unsafe { core::ptr::write_bytes(readfds as *mut u8, 0, read_bytes) };
            }
            if writefds != 0 {
                unsafe { core::ptr::write_bytes(writefds as *mut u8, 0, read_bytes) };
            }
            if exceptfds != 0 {
                unsafe { core::ptr::write_bytes(exceptfds as *mut u8, 0, read_bytes) };
            }
        };

        // Blocking path: check readiness first, then yield if not ready.
        if self.block_fn.is_some() {
            // Initial check — return immediately if fds are already ready.
            let ready = self.select_check_once(nfds, readfds, writefds, exceptfds);
            if ready > 0 {
                return ready;
            }

            let start_ms = self.poll_fn.map_or(0, |pf| pf());
            let deadline = if timeout_ms == u64::MAX {
                u64::MAX // NULL timeout = infinite wait
            } else {
                start_ms.saturating_add(timeout_ms)
            };

            loop {
                // Restore input fd_sets before each check (previous iteration may have cleared bits).
                if readfds != 0 && read_bytes > 0 {
                    let dst =
                        unsafe { core::slice::from_raw_parts_mut(readfds as *mut u8, read_bytes) };
                    dst.copy_from_slice(&saved_readfds[..read_bytes]);
                }
                if writefds != 0 && read_bytes > 0 {
                    let dst =
                        unsafe { core::slice::from_raw_parts_mut(writefds as *mut u8, read_bytes) };
                    dst.copy_from_slice(&saved_writefds[..read_bytes]);
                }
                if exceptfds != 0 && read_bytes > 0 {
                    let dst = unsafe {
                        core::slice::from_raw_parts_mut(exceptfds as *mut u8, read_bytes)
                    };
                    dst.copy_from_slice(&saved_exceptfds[..read_bytes]);
                }

                match self.block_until(BLOCK_OP_POLL, -1) {
                    BlockResult::Ready => {
                        let ready = self.select_check_once(nfds, readfds, writefds, exceptfds);
                        if ready > 0 {
                            return ready;
                        }
                        // Check timeout.
                        if timeout_ms != u64::MAX {
                            let now = self.poll_fn.map_or(deadline, |pf| pf());
                            if now >= deadline {
                                clear_fdsets(readfds, writefds, exceptfds, read_bytes);
                                return 0;
                            }
                        }
                        // No fds ready, timeout not expired — re-block.
                    }
                    BlockResult::Interrupted => {
                        clear_fdsets(readfds, writefds, exceptfds, read_bytes);
                        return 0;
                    }
                }
            }
        } else {
            // No scheduler — do one check and return.
            self.select_check_once(nfds, readfds, writefds, exceptfds)
        }
    }

    /// Single-pass readiness check for select(). Clears bits for non-ready fds,
    /// returns count of ready fds.
    fn select_check_once(&self, nfds: i32, readfds: u64, writefds: u64, exceptfds: u64) -> i64 {
        let mut ready = 0i64;
        let bytes = (nfds as usize).div_ceil(8);

        // Check readfds: clear bits for fds that are NOT readable.
        if readfds != 0 {
            let set = unsafe { core::slice::from_raw_parts_mut(readfds as *mut u8, bytes) };
            for fd in 0..nfds {
                let byte_idx = fd as usize / 8;
                let bit_idx = fd as usize % 8;
                if set[byte_idx] & (1 << bit_idx) != 0 {
                    if self.is_fd_readable(fd) {
                        ready += 1;
                    } else {
                        set[byte_idx] &= !(1 << bit_idx);
                    }
                }
            }
        }

        // Check writefds: clear bits for fds that are NOT writable.
        if writefds != 0 {
            let set = unsafe { core::slice::from_raw_parts_mut(writefds as *mut u8, bytes) };
            for fd in 0..nfds {
                let byte_idx = fd as usize / 8;
                let bit_idx = fd as usize % 8;
                if set[byte_idx] & (1 << bit_idx) != 0 {
                    if self.is_fd_writable(fd) {
                        ready += 1;
                    } else {
                        set[byte_idx] &= !(1 << bit_idx);
                    }
                }
            }
        }

        // Clear exceptfds — we never report exceptional conditions.
        if exceptfds != 0 {
            unsafe {
                core::ptr::write_bytes(exceptfds as *mut u8, 0, bytes);
            }
        }

        ready
    }

    /// Check if an fd is ready for reading (has data or EOF).
    fn is_fd_readable(&self, fd: i32) -> bool {
        let entry = match self.fd_table.get(&fd) {
            Some(e) => e,
            None => return false,
        };
        match &entry.kind {
            FdKind::PipeRead { pipe_id } => {
                let buf_nonempty = self
                    .pipes
                    .get(pipe_id)
                    .map(|b| !b.is_empty())
                    .unwrap_or(false);
                if buf_nonempty {
                    return true;
                }
                // EOF: write end is closed (no PipeWrite fd references this pipe_id).
                !self.fd_table.values().any(
                    |e| matches!(&e.kind, FdKind::PipeWrite { pipe_id: pid } if *pid == *pipe_id),
                )
            }
            FdKind::Socket { socket_id } => {
                if let Some(state) = self.sockets.get(socket_id) {
                    if let Some(h) = state.tcp_handle {
                        let tcp_state = self.tcp.tcp_state(h);
                        // Listener: readable if a connection is ready to accept.
                        if state.listening {
                            return tcp_state == TcpSocketState::Established;
                        }
                        // Data socket: readable if recv buffer has data or
                        // connection is shutting down (CloseWait/Closing/Closed).
                        return self.tcp.tcp_can_recv(h)
                            || tcp_state == TcpSocketState::CloseWait
                            || tcp_state == TcpSocketState::Closing
                            || tcp_state == TcpSocketState::Closed;
                    }
                    if let Some(h) = state.udp_handle {
                        return self.tcp.udp_can_recv(h);
                    }
                }
                // Non-TCP/UDP sockets (AF_UNIX stubs, socketpair): always ready.
                true
            }
            // Pipe write-end is not readable.
            FdKind::PipeWrite { .. } => false,
            // Serial/stdout/stderr, eventfd, timerfd, signalfd, files: always readable.
            _ => true,
        }
    }

    /// Check if an fd is ready for writing (buffer space available).
    fn is_fd_writable(&self, fd: i32) -> bool {
        let entry = match self.fd_table.get(&fd) {
            Some(e) => e,
            None => return false,
        };
        match &entry.kind {
            FdKind::PipeWrite { pipe_id } => {
                let has_reader = self.fd_table.values().any(
                    |e| matches!(&e.kind, FdKind::PipeRead { pipe_id: id } if *id == *pipe_id),
                );
                if !has_reader {
                    return true; // unblock → write returns EPIPE
                }
                const PIPE_BUF_CAP: usize = 65536;
                self.pipes
                    .get(pipe_id)
                    .map(|b| b.len() < PIPE_BUF_CAP)
                    .unwrap_or(true)
            }
            // Pipe read-end is not writable.
            FdKind::PipeRead { .. } => false,
            FdKind::Socket { socket_id } => {
                if let Some(state) = self.sockets.get(socket_id) {
                    if let Some(h) = state.tcp_handle {
                        let tcp_state = self.tcp.tcp_state(h);
                        return !state.listening
                            && self.tcp.tcp_can_send(h)
                            && (tcp_state == TcpSocketState::Established
                                || tcp_state == TcpSocketState::CloseWait);
                    }
                    if let Some(h) = state.udp_handle {
                        return self.tcp.udp_can_send(h);
                    }
                }
                // Non-TCP/UDP sockets (AF_UNIX stubs, socketpair): always ready.
                true
            }
            // Everything else: always writable.
            _ => true,
        }
    }

    /// Check if a TCP connect has reached a terminal state (success or
    /// failure).  Returns true when the socket is `Established` (handshake
    /// done) or in any closing/closed state (connection refused, RST, etc.).
    /// Used by blocking `sys_connect` so that a failed connection returns
    /// an error immediately instead of spinning for the full 30-second cap.
    fn is_fd_connect_done(&self, fd: i32) -> bool {
        let entry = match self.fd_table.get(&fd) {
            Some(e) => e,
            None => return false,
        };
        if let FdKind::Socket { socket_id } = &entry.kind {
            if let Some(state) = self.sockets.get(socket_id) {
                if let Some(h) = state.tcp_handle {
                    let tcp_state = self.tcp.tcp_state(h);
                    return tcp_state == TcpSocketState::Established
                        || tcp_state == TcpSocketState::CloseWait
                        || tcp_state == TcpSocketState::Closing
                        || tcp_state == TcpSocketState::Closed;
                }
            }
        }
        false
    }

    /// Check if a blocked task's wait condition is satisfied.
    ///
    /// Called by the system task's wake-check loop. `op` and `fd` match
    /// the values passed to `block_fn`:
    /// - 0 = FdReadable(fd)
    /// - 1 = FdWritable(fd)
    /// - 2 = FdConnectDone(fd)
    /// - 3 = PollWait (always returns true — caller handles network-change gating)
    pub fn is_wait_ready(&self, op: u8, fd: i32) -> bool {
        match op {
            0 => self.is_fd_readable(fd),
            1 => self.is_fd_writable(fd),
            2 => self.is_fd_connect_done(fd),
            3 => true,
            _ => false,
        }
    }

    /// Linux sched_getaffinity(2): get CPU affinity mask.
    ///
    /// Writes a single-CPU bitmask (bit 0 set) to the user buffer and
    /// returns 8 (size of the mask in bytes). Returns EINVAL if the
    /// buffer is too small.
    fn sys_sched_getaffinity(&mut self, cpusetsize: u64, mask: u64) -> i64 {
        // Kernel cpumask size: 8 bytes supports up to 64 CPUs.
        // The raw syscall returns this fixed size, not the user buffer size.
        const CPUMASK_SIZE: usize = 8;

        if mask == 0 {
            return EFAULT;
        }
        if (cpusetsize as usize) < CPUMASK_SIZE {
            return EINVAL;
        }
        // Write the kernel cpumask: CPU 0 set, remaining bits zero.
        let mut buf = [0u8; CPUMASK_SIZE];
        buf[0] = 1; // CPU 0
        self.backend.vm_write_bytes(mask, &buf);
        CPUMASK_SIZE as i64
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

    /// Linux uname(2): fill a `struct utsname` buffer with system identity.
    ///
    /// Each of the 6 fields is a 65-byte null-terminated C string (390 bytes total).
    /// We report "Linux" as sysname for compatibility — programs check this.
    fn sys_uname(&mut self, buf_ptr: usize) -> i64 {
        if buf_ptr == 0 {
            return EFAULT;
        }

        // struct utsname: 6 fields × 65 bytes = 390 bytes
        const FIELD_LEN: usize = 65;
        const UTSNAME_SIZE: usize = FIELD_LEN * 6;

        let mut buf = [0u8; UTSNAME_SIZE];

        // Helper: copy a string into a 65-byte field (already zero-filled).
        fn write_field(buf: &mut [u8], offset: usize, value: &[u8]) {
            let len = value.len().min(64); // leave room for NUL terminator
            buf[offset..offset + len].copy_from_slice(&value[..len]);
        }

        write_field(&mut buf, 0, b"Linux"); // sysname
        write_field(&mut buf, FIELD_LEN, b"harmony"); // nodename
        write_field(&mut buf, FIELD_LEN * 2, b"6.1.0-harmony"); // release
        write_field(&mut buf, FIELD_LEN * 3, b"#1 SMP"); // version
        #[cfg(target_arch = "x86_64")]
        write_field(&mut buf, FIELD_LEN * 4, b"x86_64"); // machine
        #[cfg(target_arch = "aarch64")]
        write_field(&mut buf, FIELD_LEN * 4, b"aarch64"); // machine
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        write_field(&mut buf, FIELD_LEN * 4, b"unknown"); // machine
        write_field(&mut buf, FIELD_LEN * 5, b"(none)"); // domainname

        self.backend.vm_write_bytes(buf_ptr as u64, &buf);
        0
    }

    /// Linux clock_gettime(2): write a `struct timespec` to the buffer.
    ///
    /// Supports CLOCK_REALTIME (0) and CLOCK_MONOTONIC (1). Uses a
    /// deterministic monotonic counter that increments by 1 ms per call.
    fn sys_clock_gettime(&mut self, clockid: i32, tp_ptr: usize) -> i64 {
        if tp_ptr == 0 {
            return EFAULT;
        }

        let ns = match clockid {
            CLOCK_REALTIME => {
                let ns = self.realtime_ns;
                self.realtime_ns = ns.wrapping_add(1_000_000);
                ns
            }
            CLOCK_MONOTONIC => {
                let ns = self.monotonic_ns;
                self.monotonic_ns = ns.wrapping_add(1_000_000);
                ns
            }
            _ => return EINVAL,
        };

        let tv_sec = ns / 1_000_000_000;
        let tv_nsec = ns % 1_000_000_000;

        // struct timespec: 16 bytes (u64 tv_sec + u64 tv_nsec), LE
        let mut buf = [0u8; 16];
        buf[0..8].copy_from_slice(&tv_sec.to_le_bytes());
        buf[8..16].copy_from_slice(&tv_nsec.to_le_bytes());
        self.backend.vm_write_bytes(tp_ptr as u64, &buf);

        0
    }

    /// Linux clock_getres(2): write clock resolution as a `struct timespec`.
    ///
    /// Reports 1 ms resolution for CLOCK_REALTIME and CLOCK_MONOTONIC.
    /// A null `tp` is allowed — Linux uses this to validate the clock ID.
    fn sys_clock_getres(&mut self, clockid: i32, tp_ptr: usize) -> i64 {
        match clockid {
            CLOCK_REALTIME | CLOCK_MONOTONIC => {
                if tp_ptr != 0 {
                    let mut buf = [0u8; 16];
                    buf[0..8].copy_from_slice(&0u64.to_le_bytes()); // tv_sec = 0
                    buf[8..16].copy_from_slice(&1_000_000u64.to_le_bytes()); // tv_nsec = 1ms
                    self.backend.vm_write_bytes(tp_ptr as u64, &buf);
                }
                0
            }
            _ => EINVAL,
        }
    }
}

#[cfg(not(feature = "page-16k"))]
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn no_tcp_implements_udp_provider() {
        use harmony_netstack::udp::UdpProvider;
        let mut no_tcp = NoTcp;
        assert!(no_tcp.udp_create().is_err());
    }

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

    #[cfg(not(feature = "page-16k"))]
    #[test]
    fn arena_brk_extend_returns_new_brk() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::with_arena(mock, 64 * 1024);
        let base = lx.handle_syscall(12, [0, 0, 0, 0, 0, 0]) as u64;
        let new_brk = lx.handle_syscall(12, [base + 8192, 0, 0, 0, 0, 0]);
        assert_eq!(new_brk as u64, base + 8192);
    }

    #[cfg(not(feature = "page-16k"))]
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
    fn sys_close_clunks_chardev_fd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();
        // Closing stdout should clunk the fid and remove the fd
        assert!(lx.has_fd(1));
        lx.handle_syscall(3, [1, 0, 0, 0, 0, 0]);
        assert!(!lx.has_fd(1));
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
        // how=SIG_BLOCK(0), set=0, oldset=0, sigsetsize=8 — no-op but valid
        let result = lx.handle_syscall(14, [0, 0, 0, 8, 0, 0]);
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

    #[cfg(not(feature = "page-16k"))]
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

    #[cfg(not(feature = "page-16k"))]
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

    #[cfg(not(feature = "page-16k"))]
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

    #[cfg(not(feature = "page-16k"))]
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

        // Open a regular file (not chardev) via openat to get fd 3
        let path = b"/data/file.txt\0";
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

        let path = b"/data/file.txt\0";
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

        // Open a regular file to get a seekable fd
        let path = b"/data/file.txt\0";
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
        // /dev/serial/log is a chardev — st_mode should be S_IFCHR | 0o666
        #[cfg(target_arch = "x86_64")]
        const ST_MODE_OFFSET: usize = 24;
        #[cfg(not(target_arch = "x86_64"))]
        const ST_MODE_OFFSET: usize = 16;
        let o = ST_MODE_OFFSET;
        let st_mode =
            u32::from_le_bytes([statbuf[o], statbuf[o + 1], statbuf[o + 2], statbuf[o + 3]]);
        assert_eq!(
            st_mode, 0o020666,
            "path-based stat on chardev should report S_IFCHR"
        );
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
    fn sys_newfstatat_at_empty_path_at_fdcwd_stats_cwd() {
        let mut mock = MockBackend::new();
        mock.directory_paths
            .insert(alloc::string::String::from("/nix/store"));
        let mut lx = Linuxulator::new(mock);
        lx.cwd = alloc::string::String::from("/nix/store");
        #[cfg(target_arch = "x86_64")]
        let mut statbuf = [0u8; 144];
        #[cfg(not(target_arch = "x86_64"))]
        let mut statbuf = [0u8; 128];
        let empty = b"\0";
        let at_empty_path: i32 = 0x1000;
        let ret = lx.dispatch_syscall(LinuxSyscall::Newfstatat {
            dirfd: -100, // AT_FDCWD
            pathname: empty.as_ptr() as u64,
            statbuf: statbuf.as_mut_ptr() as u64,
            flags: at_empty_path,
        });
        assert_eq!(ret, 0);
        // Should have walked the cwd path
        assert_eq!(lx.backend().walks[0].0, "/nix/store");
    }

    #[test]
    fn sys_newfstatat_null_pathname_at_empty_path_at_fdcwd_stats_cwd() {
        let mut mock = MockBackend::new();
        mock.directory_paths
            .insert(alloc::string::String::from("/nix/store"));
        let mut lx = Linuxulator::new(mock);
        lx.cwd = alloc::string::String::from("/nix/store");
        #[cfg(target_arch = "x86_64")]
        let mut statbuf = [0u8; 144];
        #[cfg(not(target_arch = "x86_64"))]
        let mut statbuf = [0u8; 128];
        let at_empty_path: i32 = 0x1000;
        let ret = lx.dispatch_syscall(LinuxSyscall::Newfstatat {
            dirfd: -100, // AT_FDCWD
            pathname: 0, // NULL
            statbuf: statbuf.as_mut_ptr() as u64,
            flags: at_empty_path,
        });
        assert_eq!(ret, 0);
        assert_eq!(lx.backend().walks[0].0, "/nix/store");
    }

    #[test]
    fn sys_newfstatat_absolute_path_ignores_invalid_dirfd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        #[cfg(target_arch = "x86_64")]
        let mut statbuf = [0u8; 144];
        #[cfg(not(target_arch = "x86_64"))]
        let mut statbuf = [0u8; 128];
        let path = b"/dev/serial/log\0";
        // dirfd=999 (invalid) with absolute path — should succeed
        let ret = lx.dispatch_syscall(LinuxSyscall::Newfstatat {
            dirfd: 999,
            pathname: path.as_ptr() as u64,
            statbuf: statbuf.as_mut_ptr() as u64,
            flags: 0,
        });
        assert_eq!(ret, 0);
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

    #[test]
    fn sys_faccessat_absolute_path_ignores_invalid_dirfd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let path = b"/dev/serial/log\0";
        let ret = lx.dispatch_syscall(LinuxSyscall::Faccessat {
            dirfd: 999, // invalid fd, but path is absolute
            pathname: path.as_ptr() as u64,
            mode: 0,
        });
        assert_eq!(ret, 0);
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
            other => panic!(
                "expected Readlink for zero-extended AT_FDCWD, got {:?}",
                other
            ),
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

#[cfg(not(feature = "page-16k"))]
#[cfg(test)]
mod integration_tests {
    use super::*;
    use harmony_identity::PqPrivateIdentity;
    use harmony_microkernel::echo::EchoServer;
    use harmony_microkernel::kernel::Kernel;
    use harmony_microkernel::key_hierarchy::{AttestationPair, HardwareAcceptance, OwnerClaim};
    use harmony_microkernel::serial_server::SerialServer;
    use harmony_microkernel::vm::buddy::BuddyAllocator;
    use harmony_microkernel::vm::cap_tracker::MemoryBudget;
    use harmony_microkernel::vm::manager::AddressSpaceManager;
    use harmony_microkernel::vm::mock::MockPageTable;
    use harmony_microkernel::vm::{PhysAddr, PAGE_SIZE as VM_PAGE_SIZE};
    use harmony_unikernel::KernelEntropy;

    /// Extract the 9P fid from a File-backed fd (panics for non-File kinds).
    fn test_fid(lx: &Linuxulator<impl SyscallBackend>, fd: i32) -> Fid {
        match &lx.fd_table.get(&fd).unwrap().kind {
            FdKind::File { fid, .. } => *fid,
            _ => panic!("expected File fd for fd {fd}"),
        }
    }

    /// Create a test VM manager with 64 frames.
    fn make_test_vm() -> AddressSpaceManager<MockPageTable> {
        let buddy = BuddyAllocator::new(PhysAddr(0x10_0000), 64).unwrap();
        AddressSpaceManager::new(buddy)
    }

    fn make_test_hierarchy(
        entropy: &mut KernelEntropy<impl FnMut(&mut [u8])>,
    ) -> (PqPrivateIdentity, PqPrivateIdentity, AttestationPair) {
        let owner = PqPrivateIdentity::generate(entropy);
        let owner_addr = owner.public_identity().address_hash;

        let hardware = PqPrivateIdentity::generate(entropy);
        let hw_addr = hardware.public_identity().address_hash;

        let nonce = [0xAA; 16];
        let mut claim = OwnerClaim {
            owner_address: owner_addr,
            hardware_address: hw_addr,
            claimed_at: 0,
            owner_index: 0,
            nonce,
            signature: [0u8; 3309],
        };
        let sig = owner.sign(&claim.signable_bytes()).unwrap();
        claim.signature.copy_from_slice(&sig);

        let mut acceptance = HardwareAcceptance {
            hardware_address: hw_addr,
            owner_address: owner_addr,
            accepted_at: 0,
            owner_claim_hash: claim.content_hash(),
            signature: [0u8; 3309],
        };
        let sig = hardware.sign(&acceptance.signable_bytes()).unwrap();
        acceptance.signature.copy_from_slice(&sig);

        drop(owner);

        let session = PqPrivateIdentity::generate(entropy);

        let attestation = AttestationPair {
            owner_claim: claim,
            hardware_acceptance: acceptance,
        };
        (hardware, session, attestation)
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
            self.kernel.vm_unmap_partial(self.pid, VirtAddr(vaddr), len)
        }

        fn vm_mprotect(&mut self, vaddr: u64, len: usize, flags: PageFlags) -> Result<(), VmError> {
            use harmony_microkernel::vm::VirtAddr;
            self.kernel
                .vm_protect_partial(self.pid, VirtAddr(vaddr), len, flags)
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
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

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
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        let mut kernel = Kernel::new(hw, session, attestation, make_test_vm());

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
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        // 256 frames = 1 MiB physical
        let buddy = BuddyAllocator::new(PhysAddr(0x10_0000), 256).unwrap();
        let vm = AddressSpaceManager::new(buddy);
        let mut kernel = Kernel::new(hw, session, attestation, vm);

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

    #[cfg(not(feature = "page-16k"))]
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

    #[cfg(not(feature = "page-16k"))]
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

    #[cfg(not(feature = "page-16k"))]
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
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        // 256 frames total
        let buddy = BuddyAllocator::new(PhysAddr(0x10_0000), 256).unwrap();
        let vm = AddressSpaceManager::new(buddy);
        let mut kernel = Kernel::new(hw, session, attestation, vm);

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

    #[cfg(not(feature = "page-16k"))]
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

    #[cfg(not(feature = "page-16k"))]
    #[test]
    fn test_elf_loading_with_real_vm() {
        use crate::elf::{parse_elf, SegmentFlags};
        use harmony_microkernel::vm::{FrameClassification, VirtAddr};

        let mut entropy = test_entropy();
        let (hw, session, attestation) = make_test_hierarchy(&mut entropy);
        // Large frame pool for ELF loading.
        let buddy = BuddyAllocator::new(PhysAddr(0x10_0000), 256).unwrap();
        let vm = AddressSpaceManager::new(buddy);
        let mut kernel = Kernel::new(hw, session, attestation, vm);

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
        lx.insert_test_fd(
            3,
            FdEntry {
                kind: FdKind::File {
                    fid: dir_fid,
                    offset: 0,
                    path: Some(alloc::string::String::from("/test")),
                    file_type: FileType::Directory,
                },
                flags: 0,
                nonblock: false,
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
        lx.insert_test_fd(
            3,
            FdEntry {
                kind: FdKind::File {
                    fid: dir_fid,
                    offset: 0,
                    path: Some(alloc::string::String::from("/empty")),
                    file_type: FileType::Directory,
                },
                flags: 0,
                nonblock: false,
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

    #[test]
    fn sys_openat_propagates_o_cloexec() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let path = b"/tmp/test\0";
        let fd = lx.dispatch_syscall(LinuxSyscall::Openat {
            dirfd: -100,
            pathname: path.as_ptr() as u64,
            flags: O_CLOEXEC,
        });
        assert!(fd >= 0);
        // F_GETFD should return FD_CLOEXEC
        let flags = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: fd as i32,
            cmd: 1, // F_GETFD
            arg: 0,
        });
        assert_eq!(flags, FD_CLOEXEC as i64);
    }

    #[test]
    fn sys_openat_without_cloexec_has_zero_flags() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let path = b"/tmp/test\0";
        let fd = lx.dispatch_syscall(LinuxSyscall::Openat {
            dirfd: -100,
            pathname: path.as_ptr() as u64,
            flags: 0,
        });
        assert!(fd >= 0);
        let flags = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: fd as i32,
            cmd: 1, // F_GETFD
            arg: 0,
        });
        assert_eq!(flags, 0);
    }

    // ── process identity syscall tests ────────────────────────────

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_getpid_returns_one() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // x86_64 nr 39
        let result = lx.handle_syscall(39, [0; 6]);
        assert_eq!(result, 1);
    }

    #[test]
    fn sys_getpid_dispatch() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.dispatch_syscall(LinuxSyscall::Getpid);
        assert_eq!(result, 1);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_getppid_returns_zero() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // x86_64 nr 110
        let result = lx.handle_syscall(110, [0; 6]);
        assert_eq!(result, 0);
    }

    #[test]
    fn sys_getppid_dispatch() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.dispatch_syscall(LinuxSyscall::Getppid);
        assert_eq!(result, 0);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_gettid_returns_one() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // x86_64 nr 186
        let result = lx.handle_syscall(186, [0; 6]);
        assert_eq!(result, 1);
    }

    #[test]
    fn sys_gettid_dispatch() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.dispatch_syscall(LinuxSyscall::Gettid);
        assert_eq!(result, 1);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_getuid_returns_zero() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // x86_64 nr 102
        let result = lx.handle_syscall(102, [0; 6]);
        assert_eq!(result, 0);
    }

    #[test]
    fn sys_getuid_dispatch() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.dispatch_syscall(LinuxSyscall::Getuid);
        assert_eq!(result, 0);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_geteuid_returns_zero() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // x86_64 nr 107
        let result = lx.handle_syscall(107, [0; 6]);
        assert_eq!(result, 0);
    }

    #[test]
    fn sys_geteuid_dispatch() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.dispatch_syscall(LinuxSyscall::Geteuid);
        assert_eq!(result, 0);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_getgid_returns_zero() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // x86_64 nr 104
        let result = lx.handle_syscall(104, [0; 6]);
        assert_eq!(result, 0);
    }

    #[test]
    fn sys_getgid_dispatch() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.dispatch_syscall(LinuxSyscall::Getgid);
        assert_eq!(result, 0);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_getegid_returns_zero() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // x86_64 nr 108
        let result = lx.handle_syscall(108, [0; 6]);
        assert_eq!(result, 0);
    }

    #[test]
    fn sys_getegid_dispatch() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.dispatch_syscall(LinuxSyscall::Getegid);
        assert_eq!(result, 0);
    }

    // ── madvise tests ─────────────────────────────────────────────

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_madvise_returns_zero() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // x86_64 nr 28: madvise(addr, len, advice)
        let result = lx.handle_syscall(28, [0x1000, 4096, 0, 0, 0, 0]);
        assert_eq!(result, 0);
    }

    #[test]
    fn sys_madvise_dispatch() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.dispatch_syscall(LinuxSyscall::Madvise {
            addr: 0x1000,
            len: 4096,
            advice: 4, // MADV_DONTNEED
        });
        assert_eq!(result, 0);
    }

    // ── futex tests ───────────────────────────────────────────────

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_futex_wake_returns_zero() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // x86_64 nr 202: futex(uaddr, FUTEX_WAKE=1, val, ...)
        let result = lx.handle_syscall(202, [0x1000, 1, 1, 0, 0, 0]);
        assert_eq!(result, 0);
    }

    #[test]
    fn sys_futex_wake_dispatch() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.dispatch_syscall(LinuxSyscall::Futex {
            uaddr: 0x1000,
            op: 1, // FUTEX_WAKE
            val: 1,
        });
        assert_eq!(result, 0);
    }

    #[test]
    fn sys_futex_wake_private_returns_zero() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // FUTEX_WAKE | FUTEX_PRIVATE_FLAG = 1 | 128 = 129
        let result = lx.dispatch_syscall(LinuxSyscall::Futex {
            uaddr: 0x1000,
            op: 129,
            val: 1,
        });
        assert_eq!(result, 0);
    }

    #[test]
    fn sys_futex_wait_returns_eagain() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // FUTEX_WAIT = 0. Single-threaded: always returns EAGAIN.
        let val: u32 = 42;
        let result = lx.dispatch_syscall(LinuxSyscall::Futex {
            uaddr: &val as *const u32 as u64,
            op: 0,
            val: 42,
        });
        assert_eq!(result, EAGAIN);
    }

    #[test]
    fn sys_futex_unknown_cmd_returns_enosys() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // FUTEX_LOCK_PI = 6
        let result = lx.dispatch_syscall(LinuxSyscall::Futex {
            uaddr: 0x1000,
            op: 6,
            val: 0,
        });
        assert_eq!(result, ENOSYS);
    }

    // ── sched_getaffinity tests ───────────────────────────────────

    #[test]
    fn sys_sched_getaffinity_writes_mask() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut buf = [0u8; 8];
        let result = lx.dispatch_syscall(LinuxSyscall::SchedGetaffinity {
            pid: 0,
            cpusetsize: 8,
            mask: buf.as_mut_ptr() as u64,
        });
        assert_eq!(result, 8);
        // Bit 0 should be set (CPU 0), rest zero.
        assert_eq!(buf[0], 1);
        assert_eq!(buf[1..], [0; 7]);
    }

    #[test]
    fn sys_sched_getaffinity_larger_buffer() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut buf = [0xFFu8; 128];
        let result = lx.dispatch_syscall(LinuxSyscall::SchedGetaffinity {
            pid: 0,
            cpusetsize: 128,
            mask: buf.as_mut_ptr() as u64,
        });
        // Returns kernel cpumask size (8), not user buffer size.
        assert_eq!(result, 8);
        // First 8 bytes: CPU 0 set, rest of cpumask zero.
        assert_eq!(buf[0], 1);
        assert_eq!(buf[1..8], [0; 7]);
        // Bytes beyond cpumask are untouched.
        assert_eq!(buf[8..], [0xFF; 120]);
    }

    #[test]
    fn sys_sched_getaffinity_too_small() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut buf = [0u8; 4];
        let result = lx.dispatch_syscall(LinuxSyscall::SchedGetaffinity {
            pid: 0,
            cpusetsize: 4,
            mask: buf.as_mut_ptr() as u64,
        });
        assert_eq!(result, EINVAL);
    }

    #[test]
    fn sys_sched_getaffinity_null_mask() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.dispatch_syscall(LinuxSyscall::SchedGetaffinity {
            pid: 0,
            cpusetsize: 8,
            mask: 0,
        });
        assert_eq!(result, EFAULT);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn sys_sched_getaffinity_x86_64_nr() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut buf = [0u8; 8];
        // x86_64 nr 204: sched_getaffinity(pid, cpusetsize, mask)
        let result = lx.handle_syscall(204, [0, 8, buf.as_mut_ptr() as u64, 0, 0, 0]);
        assert_eq!(result, 8);
        assert_eq!(buf[0], 1);
    }

    // ── aarch64 number mapping tests ──────────────────────────────

    #[test]
    fn aarch64_getpid_mapping() {
        let syscall = LinuxSyscall::from_aarch64(172, [0; 6]);
        assert!(matches!(syscall, LinuxSyscall::Getpid));
    }

    #[test]
    fn aarch64_getppid_mapping() {
        let syscall = LinuxSyscall::from_aarch64(173, [0; 6]);
        assert!(matches!(syscall, LinuxSyscall::Getppid));
    }

    #[test]
    fn aarch64_gettid_mapping() {
        let syscall = LinuxSyscall::from_aarch64(178, [0; 6]);
        assert!(matches!(syscall, LinuxSyscall::Gettid));
    }

    #[test]
    fn aarch64_getuid_mapping() {
        let syscall = LinuxSyscall::from_aarch64(174, [0; 6]);
        assert!(matches!(syscall, LinuxSyscall::Getuid));
    }

    #[test]
    fn aarch64_geteuid_mapping() {
        let syscall = LinuxSyscall::from_aarch64(175, [0; 6]);
        assert!(matches!(syscall, LinuxSyscall::Geteuid));
    }

    #[test]
    fn aarch64_getgid_mapping() {
        let syscall = LinuxSyscall::from_aarch64(176, [0; 6]);
        assert!(matches!(syscall, LinuxSyscall::Getgid));
    }

    #[test]
    fn aarch64_getegid_mapping() {
        let syscall = LinuxSyscall::from_aarch64(177, [0; 6]);
        assert!(matches!(syscall, LinuxSyscall::Getegid));
    }

    #[test]
    fn aarch64_madvise_mapping() {
        let syscall = LinuxSyscall::from_aarch64(233, [0x1000, 4096, 0, 0, 0, 0]);
        assert!(matches!(syscall, LinuxSyscall::Madvise { .. }));
    }

    #[test]
    fn aarch64_futex_mapping() {
        let syscall = LinuxSyscall::from_aarch64(98, [0x1000, 1, 1, 0, 0, 0]);
        assert!(matches!(syscall, LinuxSyscall::Futex { .. }));
    }

    #[test]
    fn aarch64_sched_getaffinity_mapping() {
        let syscall = LinuxSyscall::from_aarch64(123, [0, 8, 0x2000, 0, 0, 0]);
        assert!(matches!(syscall, LinuxSyscall::SchedGetaffinity { .. }));
    }

    // ── uname tests ──────────────────────────────────────────────────

    #[test]
    fn sys_uname_sysname_is_linux() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut buf = [0u8; 390];
        let result = lx.dispatch_syscall(LinuxSyscall::Uname {
            buf: buf.as_mut_ptr() as u64,
        });
        assert_eq!(result, 0);
        // sysname is the first 65-byte field
        assert_eq!(&buf[0..5], b"Linux");
        assert_eq!(buf[5], 0); // null-terminated
    }

    #[test]
    fn sys_uname_nodename_is_harmony() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut buf = [0u8; 390];
        lx.dispatch_syscall(LinuxSyscall::Uname {
            buf: buf.as_mut_ptr() as u64,
        });
        // nodename at offset 65
        assert_eq!(&buf[65..72], b"harmony");
        assert_eq!(buf[72], 0);
    }

    #[test]
    fn sys_uname_machine_matches_target_arch() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut buf = [0u8; 390];
        lx.dispatch_syscall(LinuxSyscall::Uname {
            buf: buf.as_mut_ptr() as u64,
        });
        // machine field at offset 4 * 65 = 260
        #[cfg(target_arch = "x86_64")]
        assert_eq!(&buf[260..266], b"x86_64");
        #[cfg(target_arch = "aarch64")]
        assert_eq!(&buf[260..267], b"aarch64");
    }

    #[test]
    fn sys_uname_all_fields_null_terminated() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut buf = [0xFFu8; 390]; // fill with non-zero to detect missing NUL
        lx.dispatch_syscall(LinuxSyscall::Uname {
            buf: buf.as_mut_ptr() as u64,
        });
        // Each field ends at offset (i+1)*65 - 1 and must contain a NUL
        for i in 0..6 {
            let field_start = i * 65;
            let field = &buf[field_start..field_start + 65];
            // Find the string content, then verify there's a NUL in the field
            assert!(field.contains(&0), "field {} is not null-terminated", i);
        }
    }

    #[test]
    fn sys_uname_null_buffer_returns_efault() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.dispatch_syscall(LinuxSyscall::Uname { buf: 0 });
        assert_eq!(result, EFAULT);
    }

    #[test]
    fn sys_uname_release_and_version() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut buf = [0u8; 390];
        lx.dispatch_syscall(LinuxSyscall::Uname {
            buf: buf.as_mut_ptr() as u64,
        });
        // release at offset 2*65 = 130
        assert_eq!(&buf[130..143], b"6.1.0-harmony");
        // version at offset 3*65 = 195
        assert_eq!(&buf[195..201], b"#1 SMP");
    }

    #[test]
    fn x86_64_uname_mapping() {
        let syscall = LinuxSyscall::from_x86_64(63, [0x1000, 0, 0, 0, 0, 0]);
        assert!(matches!(syscall, LinuxSyscall::Uname { buf: 0x1000 }));
    }

    #[test]
    fn aarch64_uname_mapping() {
        let syscall = LinuxSyscall::from_aarch64(160, [0x2000, 0, 0, 0, 0, 0]);
        assert!(matches!(syscall, LinuxSyscall::Uname { buf: 0x2000 }));
    }

    // ── clock_gettime tests ──────────────────────────────────────────

    #[test]
    fn sys_clock_gettime_realtime_works() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut ts = [0u8; 16];
        let result = lx.dispatch_syscall(LinuxSyscall::ClockGettime {
            clockid: 0, // CLOCK_REALTIME
            tp: ts.as_mut_ptr() as u64,
        });
        assert_eq!(result, 0);
        let tv_sec = u64::from_le_bytes(ts[0..8].try_into().unwrap());
        let tv_nsec = u64::from_le_bytes(ts[8..16].try_into().unwrap());
        // First call: monotonic_ns was 0, so sec=0, nsec=0
        assert_eq!(tv_sec, 0);
        assert_eq!(tv_nsec, 0);
    }

    #[test]
    fn sys_clock_gettime_monotonic_increments() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // First call: returns ns=0, then increments to 1_000_000
        let mut ts1 = [0u8; 16];
        lx.dispatch_syscall(LinuxSyscall::ClockGettime {
            clockid: 1, // CLOCK_MONOTONIC
            tp: ts1.as_mut_ptr() as u64,
        });
        let nsec1 = u64::from_le_bytes(ts1[8..16].try_into().unwrap());
        assert_eq!(nsec1, 0);

        // Second call: returns ns=1_000_000, then increments to 2_000_000
        let mut ts2 = [0u8; 16];
        lx.dispatch_syscall(LinuxSyscall::ClockGettime {
            clockid: 1,
            tp: ts2.as_mut_ptr() as u64,
        });
        let nsec2 = u64::from_le_bytes(ts2[8..16].try_into().unwrap());
        assert_eq!(nsec2, 1_000_000);

        // Third call: returns ns=2_000_000
        let mut ts3 = [0u8; 16];
        lx.dispatch_syscall(LinuxSyscall::ClockGettime {
            clockid: 1,
            tp: ts3.as_mut_ptr() as u64,
        });
        let nsec3 = u64::from_le_bytes(ts3[8..16].try_into().unwrap());
        assert_eq!(nsec3, 2_000_000);
    }

    #[test]
    fn sys_clock_gettime_monotonic_wraps_to_seconds() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // Pre-set monotonic_ns to just under 1 second
        lx.monotonic_ns = 999_000_000;

        let mut ts = [0u8; 16];
        lx.dispatch_syscall(LinuxSyscall::ClockGettime {
            clockid: 1,
            tp: ts.as_mut_ptr() as u64,
        });
        let tv_sec = u64::from_le_bytes(ts[0..8].try_into().unwrap());
        let tv_nsec = u64::from_le_bytes(ts[8..16].try_into().unwrap());
        assert_eq!(tv_sec, 0);
        assert_eq!(tv_nsec, 999_000_000);

        // Next call should wrap to tv_sec=1
        let mut ts2 = [0u8; 16];
        lx.dispatch_syscall(LinuxSyscall::ClockGettime {
            clockid: 1,
            tp: ts2.as_mut_ptr() as u64,
        });
        let tv_sec2 = u64::from_le_bytes(ts2[0..8].try_into().unwrap());
        let tv_nsec2 = u64::from_le_bytes(ts2[8..16].try_into().unwrap());
        assert_eq!(tv_sec2, 1);
        assert_eq!(tv_nsec2, 0);
    }

    #[test]
    fn sys_clock_gettime_invalid_clock_returns_einval() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut ts = [0u8; 16];
        let result = lx.dispatch_syscall(LinuxSyscall::ClockGettime {
            clockid: 99,
            tp: ts.as_mut_ptr() as u64,
        });
        assert_eq!(result, EINVAL);
    }

    #[test]
    fn sys_clock_gettime_null_pointer_returns_efault() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.dispatch_syscall(LinuxSyscall::ClockGettime { clockid: 0, tp: 0 });
        assert_eq!(result, EFAULT);
    }

    #[test]
    fn x86_64_clock_gettime_mapping() {
        let syscall = LinuxSyscall::from_x86_64(228, [1, 0x3000, 0, 0, 0, 0]);
        assert!(matches!(
            syscall,
            LinuxSyscall::ClockGettime {
                clockid: 1,
                tp: 0x3000
            }
        ));
    }

    #[test]
    fn aarch64_clock_gettime_mapping() {
        let syscall = LinuxSyscall::from_aarch64(113, [0, 0x4000, 0, 0, 0, 0]);
        assert!(matches!(
            syscall,
            LinuxSyscall::ClockGettime {
                clockid: 0,
                tp: 0x4000
            }
        ));
    }

    // ── clock_getres tests ───────────────────────────────────────────

    #[test]
    fn sys_clock_getres_returns_1ms_resolution() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut ts = [0u8; 16];

        // CLOCK_REALTIME
        let result = lx.dispatch_syscall(LinuxSyscall::ClockGetres {
            clockid: 0,
            tp: ts.as_mut_ptr() as u64,
        });
        assert_eq!(result, 0);
        let tv_sec = u64::from_le_bytes(ts[0..8].try_into().unwrap());
        let tv_nsec = u64::from_le_bytes(ts[8..16].try_into().unwrap());
        assert_eq!(tv_sec, 0);
        assert_eq!(tv_nsec, 1_000_000);

        // CLOCK_MONOTONIC
        let mut ts2 = [0u8; 16];
        let result2 = lx.dispatch_syscall(LinuxSyscall::ClockGetres {
            clockid: 1,
            tp: ts2.as_mut_ptr() as u64,
        });
        assert_eq!(result2, 0);
        let tv_nsec2 = u64::from_le_bytes(ts2[8..16].try_into().unwrap());
        assert_eq!(tv_nsec2, 1_000_000);
    }

    #[test]
    fn sys_clock_getres_null_tp_is_ok() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // Linux allows null tp — just validates the clock ID
        let result = lx.dispatch_syscall(LinuxSyscall::ClockGetres { clockid: 0, tp: 0 });
        assert_eq!(result, 0);

        let result2 = lx.dispatch_syscall(LinuxSyscall::ClockGetres { clockid: 1, tp: 0 });
        assert_eq!(result2, 0);
    }

    #[test]
    fn sys_clock_getres_invalid_clock_returns_einval() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let result = lx.dispatch_syscall(LinuxSyscall::ClockGetres { clockid: 42, tp: 0 });
        assert_eq!(result, EINVAL);
    }

    #[test]
    fn x86_64_clock_getres_mapping() {
        let syscall = LinuxSyscall::from_x86_64(229, [1, 0x5000, 0, 0, 0, 0]);
        assert!(matches!(
            syscall,
            LinuxSyscall::ClockGetres {
                clockid: 1,
                tp: 0x5000
            }
        ));
    }

    #[test]
    fn aarch64_clock_getres_mapping() {
        let syscall = LinuxSyscall::from_aarch64(114, [0, 0x6000, 0, 0, 0, 0]);
        assert!(matches!(
            syscall,
            LinuxSyscall::ClockGetres {
                clockid: 0,
                tp: 0x6000
            }
        ));
    }

    // ── fcntl tests ─────────────────────────────────────────────────

    #[test]
    fn sys_fcntl_getfd_default_zero() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        let result = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: 1,
            cmd: 1, // F_GETFD
            arg: 0,
        });
        assert_eq!(result, 0);
    }

    #[test]
    fn sys_fcntl_setfd_then_getfd() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        // Set FD_CLOEXEC
        let result = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: 1,
            cmd: 2, // F_SETFD
            arg: 1, // FD_CLOEXEC
        });
        assert_eq!(result, 0);
        // Read it back
        let result = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: 1,
            cmd: 1, // F_GETFD
            arg: 0,
        });
        assert_eq!(result, 1);
    }

    #[test]
    fn sys_fcntl_getfl_stub_returns_zero() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        let result = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: 0,
            cmd: 3, // F_GETFL
            arg: 0,
        });
        assert_eq!(result, 0);
    }

    #[test]
    fn sys_fcntl_setfl_stub_returns_zero() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        let result = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: 0,
            cmd: 4, // F_SETFL
            arg: 0,
        });
        assert_eq!(result, 0);
    }

    #[test]
    fn sys_fcntl_unknown_cmd_returns_einval() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        let result = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: 0,
            cmd: 99,
            arg: 0,
        });
        assert_eq!(result, EINVAL);
    }

    #[test]
    fn sys_fcntl_bad_fd_returns_ebadf() {
        let mut lx = Linuxulator::new(MockBackend::new());
        // F_GETFD on non-existent fd
        assert_eq!(
            lx.dispatch_syscall(LinuxSyscall::Fcntl {
                fd: 42,
                cmd: 1,
                arg: 0,
            }),
            EBADF
        );
        // F_SETFD on non-existent fd
        assert_eq!(
            lx.dispatch_syscall(LinuxSyscall::Fcntl {
                fd: 42,
                cmd: 2,
                arg: 1,
            }),
            EBADF
        );
        // F_GETFL on non-existent fd
        assert_eq!(
            lx.dispatch_syscall(LinuxSyscall::Fcntl {
                fd: 42,
                cmd: 3,
                arg: 0,
            }),
            EBADF
        );
        // F_SETFL on non-existent fd
        assert_eq!(
            lx.dispatch_syscall(LinuxSyscall::Fcntl {
                fd: 42,
                cmd: 4,
                arg: 0,
            }),
            EBADF
        );
    }

    #[test]
    fn sys_fcntl_getfl_returns_nonblock() {
        let mut lx = Linuxulator::new(MockBackend::new());
        // Create a nonblocking socket.
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,
            sock_type: 1 | 2048, // SOCK_STREAM | SOCK_NONBLOCK
            protocol: 0,
        });
        assert!(fd >= 0);
        let result = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: fd as i32,
            cmd: 3, // F_GETFL
            arg: 0,
        });
        assert_eq!(result, 0o4000); // O_NONBLOCK
    }

    #[test]
    fn sys_fcntl_setfl_enables_nonblock() {
        let mut lx = Linuxulator::new(MockBackend::new());
        // Create a blocking socket.
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,
            sock_type: 1, // SOCK_STREAM (blocking)
            protocol: 0,
        });
        assert!(fd >= 0);
        // Set O_NONBLOCK via F_SETFL.
        let r = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: fd as i32,
            cmd: 4,      // F_SETFL
            arg: 0o4000, // O_NONBLOCK
        });
        assert_eq!(r, 0);
        // Verify F_GETFL reflects the change.
        let result = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: fd as i32,
            cmd: 3, // F_GETFL
            arg: 0,
        });
        assert_eq!(result, 0o4000);
    }

    #[test]
    fn sys_fcntl_setfl_clears_nonblock() {
        let mut lx = Linuxulator::new(MockBackend::new());
        // Create a nonblocking socket.
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,
            sock_type: 1 | 2048, // SOCK_STREAM | SOCK_NONBLOCK
            protocol: 0,
        });
        assert!(fd >= 0);
        // Clear O_NONBLOCK via F_SETFL.
        let r = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: fd as i32,
            cmd: 4, // F_SETFL
            arg: 0, // no flags
        });
        assert_eq!(r, 0);
        // Verify F_GETFL is 0.
        let result = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: fd as i32,
            cmd: 3,
            arg: 0,
        });
        assert_eq!(result, 0);
        // Verify the entry is actually blocking.
        let entry = lx.fd_table.get(&(fd as i32)).unwrap();
        assert!(!entry.nonblock);
    }

    // ── dup tests ───────────────────────────────────────────────────

    #[test]
    fn sys_dup_returns_lowest_free_fd() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        // fds 0, 1, 2 are in use; dup should return 3
        let result = lx.dispatch_syscall(LinuxSyscall::Dup { oldfd: 1 });
        assert_eq!(result, 3);
        assert!(lx.has_fd(3));
    }

    #[test]
    fn sys_dup_shares_fid() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        let original_fid = test_fid(&lx, 1);
        let newfd = lx.dispatch_syscall(LinuxSyscall::Dup { oldfd: 1 });
        assert!(newfd >= 0);
        let new_fid = test_fid(&lx, newfd as i32);
        assert_eq!(original_fid, new_fid, "dup should share the same fid");
    }

    #[test]
    fn sys_dup_does_not_inherit_cloexec() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        // Set CLOEXEC on fd 1
        lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: 1,
            cmd: 2, // F_SETFD
            arg: 1, // FD_CLOEXEC
        });
        let newfd = lx.dispatch_syscall(LinuxSyscall::Dup { oldfd: 1 }) as i32;
        let new_flags = lx.fd_table.get(&newfd).unwrap().flags;
        assert_eq!(new_flags, 0, "dup should not inherit FD_CLOEXEC");
    }

    #[test]
    fn sys_dup_bad_fd_returns_ebadf() {
        let mut lx = Linuxulator::new(MockBackend::new());
        let result = lx.dispatch_syscall(LinuxSyscall::Dup { oldfd: 99 });
        assert_eq!(result, EBADF);
    }

    #[test]
    fn sys_dup_fills_gap() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        // Close fd 1 to create a gap
        lx.dispatch_syscall(LinuxSyscall::Close { fd: 1 });
        // dup should reuse fd 1 (lowest available)
        let result = lx.dispatch_syscall(LinuxSyscall::Dup { oldfd: 0 });
        assert_eq!(result, 1);
    }

    // ── dup refcount tests ───────────────────────────────────────────

    #[test]
    fn sys_dup_close_original_does_not_clunk() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        // Open a file to get fd 3 with a unique fid
        let path = b"/dev/serial/log\0";
        let fd = lx.dispatch_syscall(LinuxSyscall::Openat {
            dirfd: -100,
            pathname: path.as_ptr() as u64,
            flags: 0,
        }) as i32;
        assert_eq!(fd, 3);
        let fid = test_fid(&lx, fd);

        // dup fd 3 → fd 4
        let dup_fd = lx.dispatch_syscall(LinuxSyscall::Dup { oldfd: fd });
        assert_eq!(dup_fd, 4);

        // Close the original fd 3
        lx.dispatch_syscall(LinuxSyscall::Close { fd });

        // The fid should NOT have been clunked — the dup still holds it
        assert!(
            !lx.backend().clunks.contains(&fid),
            "closing original fd should not clunk fid when dup still holds it"
        );
    }

    #[test]
    fn sys_dup_close_both_clunks_once() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        // Open a file to get fd 3
        let path = b"/dev/serial/log\0";
        let fd = lx.dispatch_syscall(LinuxSyscall::Openat {
            dirfd: -100,
            pathname: path.as_ptr() as u64,
            flags: 0,
        }) as i32;
        assert_eq!(fd, 3);
        let fid = test_fid(&lx, fd);

        // dup fd 3 → fd 4
        let dup_fd = lx.dispatch_syscall(LinuxSyscall::Dup { oldfd: fd }) as i32;
        assert_eq!(dup_fd, 4);

        // Close the dup first
        lx.dispatch_syscall(LinuxSyscall::Close { fd: dup_fd });
        assert!(
            !lx.backend().clunks.contains(&fid),
            "closing first copy should not clunk yet"
        );

        // Close the original
        lx.dispatch_syscall(LinuxSyscall::Close { fd });
        // Now the fid should be clunked exactly once
        let clunk_count = lx.backend().clunks.iter().filter(|&&f| f == fid).count();
        assert_eq!(
            clunk_count, 1,
            "fid should be clunked exactly once after both fds are closed"
        );
    }

    #[test]
    fn sys_dup2_replace_decrements_refcount() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        // Open a file to get fd 3 with fid_a
        let path = b"/dev/serial/log\0";
        let fd = lx.dispatch_syscall(LinuxSyscall::Openat {
            dirfd: -100,
            pathname: path.as_ptr() as u64,
            flags: 0,
        }) as i32;
        assert_eq!(fd, 3);
        let fid_a = test_fid(&lx, fd);

        // dup fd 3 → fd 10 (fid_a refcount: 1 → 2)
        lx.dispatch_syscall(LinuxSyscall::Dup2 {
            oldfd: fd,
            newfd: 10,
        });
        assert_eq!(test_fid(&lx, 10), fid_a);

        // dup2 fd 3 → fd 10 again (replaces the previous dup)
        // The replaced fd 10's fid_a refcount should decrement (2 → 1)
        // then re-increment for the new share (1 → 2). Net: still 2.
        lx.dispatch_syscall(LinuxSyscall::Dup2 {
            oldfd: fd,
            newfd: 10,
        });

        // fid_a should NOT have been clunked (refcount never hit 0)
        assert!(
            !lx.backend().clunks.contains(&fid_a),
            "replacing a dup with same fid should not clunk"
        );

        // Close fd 10, then fd 3 — fid_a should be clunked exactly once
        lx.dispatch_syscall(LinuxSyscall::Close { fd: 10 });
        assert!(
            !lx.backend().clunks.contains(&fid_a),
            "one reference still open"
        );
        lx.dispatch_syscall(LinuxSyscall::Close { fd });
        let clunk_count = lx.backend().clunks.iter().filter(|&&f| f == fid_a).count();
        assert_eq!(clunk_count, 1, "fid_a clunked exactly once");
    }

    // ── dup2 tests ──────────────────────────────────────────────────

    #[test]
    fn sys_dup2_to_specific_fd() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        let result = lx.dispatch_syscall(LinuxSyscall::Dup2 {
            oldfd: 1,
            newfd: 10,
        });
        assert_eq!(result, 10);
        assert!(lx.has_fd(10));
        let orig_fid = test_fid(&lx, 1);
        let dup_fid = test_fid(&lx, 10);
        assert_eq!(orig_fid, dup_fid);
    }

    #[test]
    fn sys_dup2_same_fd_returns_fd() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        let result = lx.dispatch_syscall(LinuxSyscall::Dup2 { oldfd: 1, newfd: 1 });
        assert_eq!(result, 1);
    }

    #[test]
    fn sys_dup2_same_fd_bad_oldfd_returns_ebadf() {
        let mut lx = Linuxulator::new(MockBackend::new());
        let result = lx.dispatch_syscall(LinuxSyscall::Dup2 {
            oldfd: 99,
            newfd: 99,
        });
        assert_eq!(result, EBADF);
    }

    #[test]
    fn sys_dup2_closes_existing_newfd() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        // fd 2 (stderr) is open. dup2(0, 2) should close stderr first.
        let stderr_fid = test_fid(&lx, 2);
        let result = lx.dispatch_syscall(LinuxSyscall::Dup2 { oldfd: 0, newfd: 2 });
        assert_eq!(result, 2);
        // The old stderr fid should have been clunked
        assert!(
            lx.backend().clunks.contains(&stderr_fid),
            "dup2 should clunk the old fd's fid"
        );
        // fd 2 now shares fd 0's fid
        let stdin_fid = test_fid(&lx, 0);
        let new_fd2_fid = test_fid(&lx, 2);
        assert_eq!(stdin_fid, new_fd2_fid);
    }

    #[test]
    fn sys_dup2_bad_oldfd_returns_ebadf() {
        let mut lx = Linuxulator::new(MockBackend::new());
        let result = lx.dispatch_syscall(LinuxSyscall::Dup2 {
            oldfd: 99,
            newfd: 10,
        });
        assert_eq!(result, EBADF);
    }

    #[test]
    fn sys_dup2_flags_not_inherited() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        // Set CLOEXEC on fd 0
        lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: 0,
            cmd: 2,
            arg: 1,
        });
        let result = lx.dispatch_syscall(LinuxSyscall::Dup2 {
            oldfd: 0,
            newfd: 10,
        });
        assert_eq!(result, 10);
        assert_eq!(lx.fd_table.get(&10).unwrap().flags, 0);
    }

    // ── dup3 tests ──────────────────────────────────────────────────

    #[test]
    fn sys_dup3_basic() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        let result = lx.dispatch_syscall(LinuxSyscall::Dup3 {
            oldfd: 1,
            newfd: 10,
            flags: 0,
        });
        assert_eq!(result, 10);
        assert!(lx.has_fd(10));
        assert_eq!(lx.fd_table.get(&10).unwrap().flags, 0);
    }

    #[test]
    fn sys_dup3_with_cloexec() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        let o_cloexec: i32 = 0o2000000;
        let result = lx.dispatch_syscall(LinuxSyscall::Dup3 {
            oldfd: 1,
            newfd: 10,
            flags: o_cloexec,
        });
        assert_eq!(result, 10);
        assert_eq!(
            lx.fd_table.get(&10).unwrap().flags,
            1,
            "dup3 with O_CLOEXEC should set FD_CLOEXEC"
        );
    }

    #[test]
    fn sys_dup3_same_fd_returns_einval() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        let result = lx.dispatch_syscall(LinuxSyscall::Dup3 {
            oldfd: 1,
            newfd: 1,
            flags: 0,
        });
        assert_eq!(result, EINVAL);
    }

    #[test]
    fn sys_dup3_invalid_flags_returns_einval() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        let result = lx.dispatch_syscall(LinuxSyscall::Dup3 {
            oldfd: 1,
            newfd: 10,
            flags: 0x42, // not O_CLOEXEC
        });
        assert_eq!(result, EINVAL);
    }

    #[test]
    fn sys_dup3_bad_oldfd_returns_ebadf() {
        let mut lx = Linuxulator::new(MockBackend::new());
        let result = lx.dispatch_syscall(LinuxSyscall::Dup3 {
            oldfd: 99,
            newfd: 10,
            flags: 0,
        });
        assert_eq!(result, EBADF);
    }

    #[test]
    fn sys_dup3_closes_existing_newfd() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        let stderr_fid = test_fid(&lx, 2);
        let result = lx.dispatch_syscall(LinuxSyscall::Dup3 {
            oldfd: 0,
            newfd: 2,
            flags: 0,
        });
        assert_eq!(result, 2);
        assert!(
            lx.backend().clunks.contains(&stderr_fid),
            "dup3 should clunk the old fd's fid"
        );
    }

    #[test]
    fn sys_dup3_shares_fid() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        let orig_fid = test_fid(&lx, 1);
        lx.dispatch_syscall(LinuxSyscall::Dup3 {
            oldfd: 1,
            newfd: 10,
            flags: 0,
        });
        let dup_fid = test_fid(&lx, 10);
        assert_eq!(orig_fid, dup_fid);
    }

    #[test]
    fn sys_dup2_negative_newfd_returns_ebadf() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        let result = lx.dispatch_syscall(LinuxSyscall::Dup2 {
            oldfd: 1,
            newfd: -1,
        });
        assert_eq!(result, EBADF);
    }

    #[test]
    fn sys_dup3_negative_newfd_returns_ebadf() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.init_stdio().unwrap();
        let result = lx.dispatch_syscall(LinuxSyscall::Dup3 {
            oldfd: 1,
            newfd: -1,
            flags: 0,
        });
        assert_eq!(result, EBADF);
    }

    #[test]
    fn sys_clock_gettime_realtime_independent_of_monotonic() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Advance monotonic clock 3 times
        let mut ts = [0u8; 16];
        for _ in 0..3 {
            lx.dispatch_syscall(LinuxSyscall::ClockGettime {
                clockid: 1, // CLOCK_MONOTONIC
                tp: ts.as_mut_ptr() as u64,
            });
        }
        let mono_nsec = u64::from_le_bytes(ts[8..16].try_into().unwrap());
        assert_eq!(mono_nsec, 2_000_000); // 3rd call returns ns=2M

        // First CLOCK_REALTIME call should start at 0, not 3M
        let mut rts = [0u8; 16];
        lx.dispatch_syscall(LinuxSyscall::ClockGettime {
            clockid: 0, // CLOCK_REALTIME
            tp: rts.as_mut_ptr() as u64,
        });
        let rt_sec = u64::from_le_bytes(rts[0..8].try_into().unwrap());
        let rt_nsec = u64::from_le_bytes(rts[8..16].try_into().unwrap());
        assert_eq!(rt_sec, 0);
        assert_eq!(rt_nsec, 0); // independent counter, starts at 0
    }

    // ── Syscall number mapping tests for fd manipulation ────────────

    #[test]
    fn from_x86_64_dup() {
        let syscall = LinuxSyscall::from_x86_64(32, [5, 0, 0, 0, 0, 0]);
        assert!(matches!(syscall, LinuxSyscall::Dup { oldfd: 5 }));
    }

    #[test]
    fn from_x86_64_dup2() {
        let syscall = LinuxSyscall::from_x86_64(33, [1, 10, 0, 0, 0, 0]);
        assert!(matches!(
            syscall,
            LinuxSyscall::Dup2 {
                oldfd: 1,
                newfd: 10
            }
        ));
    }

    #[test]
    fn from_x86_64_fcntl() {
        let syscall = LinuxSyscall::from_x86_64(72, [3, 1, 0, 0, 0, 0]);
        assert!(matches!(
            syscall,
            LinuxSyscall::Fcntl {
                fd: 3,
                cmd: 1,
                arg: 0
            }
        ));
    }

    #[test]
    fn from_x86_64_dup3() {
        let o_cloexec = 0o2000000u64;
        let syscall = LinuxSyscall::from_x86_64(292, [1, 10, o_cloexec, 0, 0, 0]);
        assert!(matches!(
            syscall,
            LinuxSyscall::Dup3 {
                oldfd: 1,
                newfd: 10,
                ..
            }
        ));
    }

    #[test]
    fn from_aarch64_dup() {
        let syscall = LinuxSyscall::from_aarch64(23, [5, 0, 0, 0, 0, 0]);
        assert!(matches!(syscall, LinuxSyscall::Dup { oldfd: 5 }));
    }

    #[test]
    fn from_aarch64_dup3() {
        let o_cloexec = 0o2000000u64;
        let syscall = LinuxSyscall::from_aarch64(24, [1, 10, o_cloexec, 0, 0, 0]);
        assert!(matches!(
            syscall,
            LinuxSyscall::Dup3 {
                oldfd: 1,
                newfd: 10,
                ..
            }
        ));
    }

    #[test]
    fn from_aarch64_fcntl() {
        let syscall = LinuxSyscall::from_aarch64(25, [3, 2, 1, 0, 0, 0]);
        assert!(matches!(
            syscall,
            LinuxSyscall::Fcntl {
                fd: 3,
                cmd: 2,
                arg: 1
            }
        ));
    }

    // ── sys_pipe2 / sys_pipe tests ───────────────────────────────────

    #[test]
    fn test_pipe2_creates_fds() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // Stack buffer to receive the two i32 fds.
        let mut fds = [0i32; 2];
        let result = lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0,
        });
        assert_eq!(result, 0);
        // Read back the fds written to our buffer.
        let read_fd = fds[0];
        let write_fd = fds[1];
        assert!(read_fd >= 0);
        assert!(write_fd >= 0);
        assert_ne!(read_fd, write_fd);
        // Both fds should be in the fd table.
        assert!(lx.has_fd(read_fd));
        assert!(lx.has_fd(write_fd));
    }

    #[test]
    fn test_pipe2_cloexec() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut fds = [0i32; 2];
        let result = lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: O_CLOEXEC as u64,
        });
        assert_eq!(result, 0);
        // Verify FD_CLOEXEC is set on both fds via fcntl F_GETFD.
        let read_flags = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: fds[0],
            cmd: 1, // F_GETFD
            arg: 0,
        });
        let write_flags = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: fds[1],
            cmd: 1, // F_GETFD
            arg: 0,
        });
        assert_eq!(read_flags, FD_CLOEXEC as i64);
        assert_eq!(write_flags, FD_CLOEXEC as i64);
    }

    #[test]
    fn test_pipe2_invalid_flags() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let mut fds = [0i32; 2];
        // Pass an invalid flag (0x1 is not O_CLOEXEC or O_NONBLOCK).
        let result = lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0x1,
        });
        assert_eq!(result, EINVAL);
    }

    #[test]
    fn from_x86_64_pipe() {
        let syscall = LinuxSyscall::from_x86_64(22, [0x1000, 0, 0, 0, 0, 0]);
        assert!(matches!(syscall, LinuxSyscall::Pipe { fds: 0x1000 }));
    }

    #[test]
    fn from_x86_64_pipe2() {
        let syscall = LinuxSyscall::from_x86_64(293, [0x2000, 0o2000000, 0, 0, 0, 0]);
        assert!(matches!(
            syscall,
            LinuxSyscall::Pipe2 {
                fds: 0x2000,
                flags: 0o2000000
            }
        ));
    }

    #[test]
    fn from_aarch64_pipe2() {
        let syscall = LinuxSyscall::from_aarch64(59, [0x3000, 0o4000, 0, 0, 0, 0]);
        assert!(matches!(
            syscall,
            LinuxSyscall::Pipe2 {
                fds: 0x3000,
                flags: 0o4000
            }
        ));
    }

    // ── Pipe read/write/close integration tests ─────────────────────

    /// Helper: create a pipe and return (read_fd, write_fd).
    fn create_pipe(lx: &mut Linuxulator<MockBackend>) -> (i32, i32) {
        let mut fds = [0i32; 2];
        let result = lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0,
        });
        assert_eq!(result, 0);
        (fds[0], fds[1])
    }

    #[test]
    fn test_pipe_write_then_read() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let (rfd, wfd) = create_pipe(&mut lx);

        // Write "hello" to the pipe.
        let data = b"hello";
        let written = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: wfd,
            buf: data.as_ptr() as u64,
            count: data.len() as u64,
        });
        assert_eq!(written, 5);

        // Read it back.
        let mut buf = [0u8; 16];
        let read = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: rfd,
            buf: buf.as_mut_ptr() as u64,
            count: buf.len() as u64,
        });
        assert_eq!(read, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn test_pipe_read_eof_after_write_close() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let (rfd, wfd) = create_pipe(&mut lx);

        // Close the write end.
        let result = lx.dispatch_syscall(LinuxSyscall::Close { fd: wfd });
        assert_eq!(result, 0);

        // Read should return 0 (EOF).
        let mut buf = [0u8; 16];
        let read = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: rfd,
            buf: buf.as_mut_ptr() as u64,
            count: buf.len() as u64,
        });
        assert_eq!(
            read, 0,
            "read from pipe with closed write end should return EOF"
        );
    }

    #[test]
    fn test_pipe_write_epipe_after_read_close() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let (rfd, wfd) = create_pipe(&mut lx);

        // Close the read end.
        let result = lx.dispatch_syscall(LinuxSyscall::Close { fd: rfd });
        assert_eq!(result, 0);

        // Write should return EPIPE.
        let data = b"hello";
        let written = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: wfd,
            buf: data.as_ptr() as u64,
            count: data.len() as u64,
        });
        assert_eq!(written, EPIPE);
    }

    #[test]
    fn test_pipe_partial_read() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let (rfd, wfd) = create_pipe(&mut lx);

        // Write 10 bytes.
        let data = b"0123456789";
        lx.dispatch_syscall(LinuxSyscall::Write {
            fd: wfd,
            buf: data.as_ptr() as u64,
            count: 10,
        });

        // Read first 5.
        let mut buf1 = [0u8; 5];
        let r1 = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: rfd,
            buf: buf1.as_mut_ptr() as u64,
            count: 5,
        });
        assert_eq!(r1, 5);
        assert_eq!(&buf1, b"01234");

        // Read remaining 5.
        let mut buf2 = [0u8; 5];
        let r2 = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: rfd,
            buf: buf2.as_mut_ptr() as u64,
            count: 5,
        });
        assert_eq!(r2, 5);
        assert_eq!(&buf2, b"56789");
    }

    #[test]
    fn test_pipe_lseek_returns_espipe() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let (rfd, wfd) = create_pipe(&mut lx);

        let result = lx.dispatch_syscall(LinuxSyscall::Lseek {
            fd: rfd,
            offset: 0,
            whence: 0,
        });
        assert_eq!(result, ESPIPE);

        let result = lx.dispatch_syscall(LinuxSyscall::Lseek {
            fd: wfd,
            offset: 0,
            whence: 0,
        });
        assert_eq!(result, ESPIPE);
    }

    #[test]
    fn test_pipe_dup_shares_buffer() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let (rfd, wfd) = create_pipe(&mut lx);

        // Dup the write end.
        let dup_wfd = lx.dispatch_syscall(LinuxSyscall::Dup { oldfd: wfd });
        assert!(dup_wfd >= 0);

        // Write from the dup'd fd.
        let data = b"duped";
        lx.dispatch_syscall(LinuxSyscall::Write {
            fd: dup_wfd as i32,
            buf: data.as_ptr() as u64,
            count: data.len() as u64,
        });

        // Read from the original read fd.
        let mut buf = [0u8; 16];
        let read = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: rfd,
            buf: buf.as_mut_ptr() as u64,
            count: buf.len() as u64,
        });
        assert_eq!(read, 5);
        assert_eq!(&buf[..5], b"duped");
    }

    #[test]
    fn test_pipe_fstat_returns_fifo() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let (rfd, _wfd) = create_pipe(&mut lx);

        // fstat the read end — should return S_IFIFO.
        let mut stat_buf = [0u8; 144]; // x86_64 stat size
        let result = lx.dispatch_syscall(LinuxSyscall::Fstat {
            fd: rfd,
            buf: stat_buf.as_mut_ptr() as u64,
        });
        assert_eq!(result, 0);

        // Read st_mode from the stat buffer.
        #[cfg(target_arch = "x86_64")]
        let mode = u32::from_le_bytes(stat_buf[24..28].try_into().unwrap());
        #[cfg(not(target_arch = "x86_64"))]
        let mode = u32::from_le_bytes(stat_buf[16..20].try_into().unwrap());

        let s_ififo: u32 = 0o010000;
        assert_eq!(
            mode & 0o170000,
            s_ififo,
            "st_mode should have S_IFIFO type, got {:#o}",
            mode
        );
    }

    // ── sys_eventfd2 tests ──────────────────────────────────────────

    #[test]
    fn test_eventfd_init_and_read() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let fd = lx.dispatch_syscall(LinuxSyscall::EventFd2 {
            initval: 42,
            flags: 0,
        });
        assert!(fd >= 0);

        // First read returns 42.
        let mut buf = [0u8; 8];
        let result = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: fd as i32,
            buf: buf.as_mut_ptr() as u64,
            count: 8,
        });
        assert_eq!(result, 8);
        assert_eq!(u64::from_le_bytes(buf), 42);

        // Second read returns EAGAIN (counter is 0 after first read).
        let result = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: fd as i32,
            buf: buf.as_mut_ptr() as u64,
            count: 8,
        });
        assert_eq!(result, EAGAIN);
    }

    #[test]
    fn test_eventfd_semaphore() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let efd_semaphore: u64 = 1;
        let fd = lx.dispatch_syscall(LinuxSyscall::EventFd2 {
            initval: 3,
            flags: efd_semaphore,
        });
        assert!(fd >= 0);

        // In semaphore mode, each read returns 1 and decrements by 1.
        for _ in 0..3 {
            let mut buf = [0u8; 8];
            let result = lx.dispatch_syscall(LinuxSyscall::Read {
                fd: fd as i32,
                buf: buf.as_mut_ptr() as u64,
                count: 8,
            });
            assert_eq!(result, 8);
            assert_eq!(u64::from_le_bytes(buf), 1);
        }

        // Fourth read: EAGAIN (counter is 0).
        let mut buf = [0u8; 8];
        let result = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: fd as i32,
            buf: buf.as_mut_ptr() as u64,
            count: 8,
        });
        assert_eq!(result, EAGAIN);
    }

    #[test]
    fn test_eventfd_write_accumulates() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let fd = lx.dispatch_syscall(LinuxSyscall::EventFd2 {
            initval: 0,
            flags: 0,
        });
        assert!(fd >= 0);

        // Write 10.
        let val: u64 = 10;
        let result = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: fd as i32,
            buf: val.to_le_bytes().as_ptr() as u64,
            count: 8,
        });
        assert_eq!(result, 8);

        // Write 20.
        let val: u64 = 20;
        let result = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: fd as i32,
            buf: val.to_le_bytes().as_ptr() as u64,
            count: 8,
        });
        assert_eq!(result, 8);

        // Read should return 30.
        let mut buf = [0u8; 8];
        let result = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: fd as i32,
            buf: buf.as_mut_ptr() as u64,
            count: 8,
        });
        assert_eq!(result, 8);
        assert_eq!(u64::from_le_bytes(buf), 30);
    }

    #[test]
    fn test_eventfd_read_zero_eagain() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let fd = lx.dispatch_syscall(LinuxSyscall::EventFd2 {
            initval: 0,
            flags: 0,
        });

        let mut buf = [0u8; 8];
        let result = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: fd as i32,
            buf: buf.as_mut_ptr() as u64,
            count: 8,
        });
        assert_eq!(result, EAGAIN);
    }

    #[test]
    fn test_eventfd_buffer_too_small() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let fd = lx.dispatch_syscall(LinuxSyscall::EventFd2 {
            initval: 42,
            flags: 0,
        });

        // Read with count < 8 returns EINVAL.
        let mut buf = [0u8; 4];
        let result = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: fd as i32,
            buf: buf.as_mut_ptr() as u64,
            count: 4,
        });
        assert_eq!(result, EINVAL);
    }

    #[test]
    fn test_eventfd_write_overflow() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let fd = lx.dispatch_syscall(LinuxSyscall::EventFd2 {
            initval: 0,
            flags: 0,
        });

        // Write near-max value.
        let val: u64 = 0xFFFFFFFFFFFFFFFE;
        let result = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: fd as i32,
            buf: val.to_le_bytes().as_ptr() as u64,
            count: 8,
        });
        assert_eq!(result, 8);

        // Writing 1 more should return EAGAIN (overflow).
        let val: u64 = 1;
        let result = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: fd as i32,
            buf: val.to_le_bytes().as_ptr() as u64,
            count: 8,
        });
        assert_eq!(result, EAGAIN);
    }

    #[test]
    fn test_eventfd_write_max_einval() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let fd = lx.dispatch_syscall(LinuxSyscall::EventFd2 {
            initval: 0,
            flags: 0,
        });

        // Writing u64::MAX returns EINVAL.
        let val: u64 = u64::MAX;
        let result = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: fd as i32,
            buf: val.to_le_bytes().as_ptr() as u64,
            count: 8,
        });
        assert_eq!(result, EINVAL);
    }

    #[test]
    fn from_x86_64_eventfd2() {
        let syscall = LinuxSyscall::from_x86_64(290, [42, 0o2000000, 0, 0, 0, 0]);
        assert!(matches!(
            syscall,
            LinuxSyscall::EventFd2 {
                initval: 42,
                flags: 0o2000000
            }
        ));
    }

    #[test]
    fn from_aarch64_eventfd2() {
        let syscall = LinuxSyscall::from_aarch64(19, [5, 1, 0, 0, 0, 0]);
        assert!(matches!(
            syscall,
            LinuxSyscall::EventFd2 {
                initval: 5,
                flags: 1
            }
        ));
    }

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

    #[test]
    fn test_socket_lifecycle() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Create socket
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 1,    // AF_UNIX
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

        // connect — AF_UNIX returns ECONNREFUSED (no daemon running)
        let r = lx.dispatch_syscall(LinuxSyscall::Connect {
            fd: client_fd as i32,
            addr: 0,
            addrlen: 0,
        });
        assert_eq!(r, -111); // ECONNREFUSED

        // shutdown — no-op stub
        let r = lx.dispatch_syscall(LinuxSyscall::Shutdown {
            fd: client_fd as i32,
            how: 2, // SHUT_RDWR
        });
        assert_eq!(r, 0);

        // close both
        assert_eq!(
            lx.dispatch_syscall(LinuxSyscall::Close {
                fd: client_fd as i32
            }),
            0
        );
        assert_eq!(
            lx.dispatch_syscall(LinuxSyscall::Close { fd: fd as i32 }),
            0
        );
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
        let r = lx.dispatch_syscall(LinuxSyscall::Sendto {
            fd,
            buf: buf.as_ptr() as u64,
            len: 64,
            flags: 0,
            dest_addr: 0,
            addrlen: 0,
        });
        assert_eq!(r, 64);
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
        let r = lx.dispatch_syscall(LinuxSyscall::Setsockopt {
            fd,
            level: 1,
            optname: 2,
            optval: 0,
            optlen: 0,
        });
        assert_eq!(r, 0);
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
        let r = lx.dispatch_syscall(LinuxSyscall::Getsockname {
            fd,
            addr: addr.as_mut_ptr() as u64,
            addrlen: &mut addrlen as *mut u32 as u64,
        });
        assert_eq!(r, 0);
        // AF_INET stub: writes sockaddr_in with AF_INET=2, 127.0.0.1
        assert_eq!(addrlen, 16);
        assert_eq!(u16::from_ne_bytes([addr[0], addr[1]]), 2); // AF_INET
        addr.fill(0xFF);
        addrlen = 16;
        let r = lx.dispatch_syscall(LinuxSyscall::Getpeername {
            fd,
            addr: addr.as_mut_ptr() as u64,
            addrlen: &mut addrlen as *mut u32 as u64,
        });
        assert_eq!(r, 0);
        assert_eq!(addrlen, 16);
        assert_eq!(u16::from_ne_bytes([addr[0], addr[1]]), 2); // AF_INET
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
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd,
            buf: buf.as_ptr() as u64,
            count: 32,
        });
        assert_eq!(r, 0);
        let r = lx.dispatch_syscall(LinuxSyscall::Write {
            fd,
            buf: buf.as_ptr() as u64,
            count: 32,
        });
        assert_eq!(r, 32);
    }

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

        // SOCK_NONBLOCK sets nonblock — verify via accept EAGAIN guard
        let fd2 = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 1,
            sock_type: 1 | 0o4000, // SOCK_STREAM | SOCK_NONBLOCK
            protocol: 0,
        }) as i32;
        assert!(fd2 >= 0);
        // listen → accept → second accept should EAGAIN (nonblock guard)
        lx.dispatch_syscall(LinuxSyscall::Listen {
            fd: fd2,
            backlog: 1,
        });
        let a1 = lx.dispatch_syscall(LinuxSyscall::Accept {
            fd: fd2,
            addr: 0,
            addrlen: 0,
        });
        assert!(a1 >= 0);
        let a2 = lx.dispatch_syscall(LinuxSyscall::Accept {
            fd: fd2,
            addr: 0,
            addrlen: 0,
        });
        assert_eq!(a2, EAGAIN);
    }

    #[test]
    fn fd_entry_nonblock_from_sock_nonblock() {
        let mut lx = Linuxulator::new(MockBackend::new());
        // SOCK_NONBLOCK = 0o4000 = 2048
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,           // AF_INET
            sock_type: 1 | 2048, // SOCK_STREAM | SOCK_NONBLOCK
            protocol: 0,
        });
        assert!(fd >= 0);
        let entry = lx.fd_table.get(&(fd as i32)).unwrap();
        assert!(entry.nonblock);
    }

    #[test]
    fn fd_entry_nonblock_default_false() {
        let mut lx = Linuxulator::new(MockBackend::new());
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,    // AF_INET
            sock_type: 1, // SOCK_STREAM (no NONBLOCK)
            protocol: 0,
        });
        assert!(fd >= 0);
        let entry = lx.fd_table.get(&(fd as i32)).unwrap();
        assert!(!entry.nonblock);
    }

    #[test]
    fn fd_entry_nonblock_from_pipe2() {
        let mut lx = Linuxulator::new(MockBackend::new());
        let mut fds = [0i32; 2];
        let result = lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0o4000, // O_NONBLOCK
        });
        assert_eq!(result, 0);
        assert!(lx.fd_table.get(&fds[0]).unwrap().nonblock);
        assert!(lx.fd_table.get(&fds[1]).unwrap().nonblock);
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

        // st_mode field: S_IFSOCK | 0o644 = 0o140644 = 0xC1A4
        #[cfg(target_arch = "x86_64")]
        let mode = u32::from_le_bytes(stat_buf[24..28].try_into().unwrap());
        #[cfg(not(target_arch = "x86_64"))]
        let mode = u32::from_le_bytes(stat_buf[16..20].try_into().unwrap());

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
            lx.dispatch_syscall(LinuxSyscall::Bind {
                fd: pipe_fd,
                addr: 0,
                addrlen: 0
            }),
            ENOTSOCK
        );
        assert_eq!(
            lx.dispatch_syscall(LinuxSyscall::Listen {
                fd: pipe_fd,
                backlog: 1
            }),
            ENOTSOCK
        );
        assert_eq!(
            lx.dispatch_syscall(LinuxSyscall::Connect {
                fd: pipe_fd,
                addr: 0,
                addrlen: 0
            }),
            ENOTSOCK
        );
        assert_eq!(
            lx.dispatch_syscall(LinuxSyscall::Sendto {
                fd: pipe_fd,
                buf: 0,
                len: 0,
                flags: 0,
                dest_addr: 0,
                addrlen: 0
            }),
            ENOTSOCK
        );
        assert_eq!(
            lx.dispatch_syscall(LinuxSyscall::Recvfrom {
                fd: pipe_fd,
                buf: 0,
                len: 0,
                flags: 0,
                src_addr: 0,
                addrlen: 0
            }),
            ENOTSOCK
        );
        assert_eq!(
            lx.dispatch_syscall(LinuxSyscall::Shutdown {
                fd: pipe_fd,
                how: 0
            }),
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

    /// Test helper for reading/writing epoll_event structs.
    #[derive(Clone, Copy)]
    #[repr(C)]
    struct EpollEventBuf {
        #[cfg(target_arch = "x86_64")]
        buf: [u8; 12],
        #[cfg(target_arch = "aarch64")]
        buf: [u8; 16],
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        buf: [u8; 12],
    }

    impl EpollEventBuf {
        fn new(events: u32, data: u64) -> Self {
            let mut s = Self {
                #[cfg(target_arch = "x86_64")]
                buf: [0u8; 12],
                #[cfg(target_arch = "aarch64")]
                buf: [0u8; 16],
                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                buf: [0u8; 12],
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
                self.buf[4],
                self.buf[5],
                self.buf[6],
                self.buf[7],
                self.buf[8],
                self.buf[9],
                self.buf[10],
                self.buf[11],
            ])
        }

        #[cfg(target_arch = "aarch64")]
        fn data(&self) -> u64 {
            u64::from_ne_bytes([
                self.buf[8],
                self.buf[9],
                self.buf[10],
                self.buf[11],
                self.buf[12],
                self.buf[13],
                self.buf[14],
                self.buf[15],
            ])
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        fn data(&self) -> u64 {
            u64::from_ne_bytes([
                self.buf[4],
                self.buf[5],
                self.buf[6],
                self.buf[7],
                self.buf[8],
                self.buf[9],
                self.buf[10],
                self.buf[11],
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

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        fn set_data(&mut self, data: u64) {
            self.buf[4..12].copy_from_slice(&data.to_ne_bytes());
        }
    }

    #[test]
    fn test_epoll_create_and_ctl() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let epfd = lx.dispatch_syscall(LinuxSyscall::EpollCreate1 { flags: 0 });
        assert!(epfd >= 0);
        assert!(lx.has_fd(epfd as i32));

        let mut fds = [0i32; 2];
        lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0,
        });

        let ev = EpollEventBuf::new(0x1, fds[0] as u64); // EPOLLIN
        let r = lx.dispatch_syscall(LinuxSyscall::EpollCtl {
            epfd: epfd as i32,
            op: 1,
            fd: fds[0],
            event: ev.as_ptr(),
        });
        assert_eq!(r, 0);

        // Duplicate ADD → EEXIST
        let r = lx.dispatch_syscall(LinuxSyscall::EpollCtl {
            epfd: epfd as i32,
            op: 1,
            fd: fds[0],
            event: ev.as_ptr(),
        });
        assert_eq!(r, EEXIST);

        // MOD
        let ev2 = EpollEventBuf::new(0x4, fds[0] as u64); // EPOLLOUT
        let r = lx.dispatch_syscall(LinuxSyscall::EpollCtl {
            epfd: epfd as i32,
            op: 2,
            fd: fds[0],
            event: ev2.as_ptr(),
        });
        assert_eq!(r, 0);

        // DEL
        let r = lx.dispatch_syscall(LinuxSyscall::EpollCtl {
            epfd: epfd as i32,
            op: 3,
            fd: fds[0],
            event: 0,
        });
        assert_eq!(r, 0);

        // DEL again → ENOENT
        let r = lx.dispatch_syscall(LinuxSyscall::EpollCtl {
            epfd: epfd as i32,
            op: 3,
            fd: fds[0],
            event: 0,
        });
        assert_eq!(r, ENOENT);

        // MOD on removed → ENOENT
        let r = lx.dispatch_syscall(LinuxSyscall::EpollCtl {
            epfd: epfd as i32,
            op: 2,
            fd: fds[0],
            event: ev.as_ptr(),
        });
        assert_eq!(r, ENOENT);
    }

    #[test]
    fn test_epoll_wait_returns_ready() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let epfd = lx.dispatch_syscall(LinuxSyscall::EpollCreate1 { flags: 0 }) as i32;

        let mut fds1 = [0i32; 2];
        let mut fds2 = [0i32; 2];
        lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds1.as_mut_ptr() as u64,
            flags: 0,
        });
        lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds2.as_mut_ptr() as u64,
            flags: 0,
        });

        let ev1 = EpollEventBuf::new(0x1, fds1[0] as u64);
        let ev2 = EpollEventBuf::new(0x4, fds2[0] as u64);
        lx.dispatch_syscall(LinuxSyscall::EpollCtl {
            epfd,
            op: 1,
            fd: fds1[0],
            event: ev1.as_ptr(),
        });
        lx.dispatch_syscall(LinuxSyscall::EpollCtl {
            epfd,
            op: 1,
            fd: fds2[0],
            event: ev2.as_ptr(),
        });

        let out = [EpollEventBuf::new(0, 0); 4];
        let n = lx.dispatch_syscall(LinuxSyscall::EpollWait {
            epfd,
            events: out[0].as_ptr(),
            maxevents: 4,
            timeout: -1,
        });
        assert_eq!(n, 2);

        let returned: alloc::collections::BTreeSet<u64> =
            out[..2].iter().map(|e| e.data()).collect();
        assert!(returned.contains(&(fds1[0] as u64)));
        assert!(returned.contains(&(fds2[0] as u64)));
    }

    #[test]
    fn test_epoll_wait_empty() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let epfd = lx.dispatch_syscall(LinuxSyscall::EpollCreate1 { flags: 0 }) as i32;

        let out = [EpollEventBuf::new(0, 0); 4];
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

        for _ in 0..3 {
            let mut fds = [0i32; 2];
            lx.dispatch_syscall(LinuxSyscall::Pipe2 {
                fds: fds.as_mut_ptr() as u64,
                flags: 0,
            });
            let ev = EpollEventBuf::new(0x1, fds[0] as u64);
            lx.dispatch_syscall(LinuxSyscall::EpollCtl {
                epfd,
                op: 1,
                fd: fds[0],
                event: ev.as_ptr(),
            });
        }

        let out = [EpollEventBuf::new(0, 0); 4];
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

        let ev = EpollEventBuf::new(0x1, 999);
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

        let mut fds = [0i32; 2];
        lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0,
        });

        let ev = EpollEventBuf::new(0x1, 0);
        let r = lx.dispatch_syscall(LinuxSyscall::EpollCtl {
            epfd: fds[0],
            op: 1,
            fd: fds[1],
            event: ev.as_ptr(),
        });
        assert_eq!(r, EINVAL);

        let out = [EpollEventBuf::new(0, 0); 4];
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
        lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0,
        });

        let magic: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let ev = EpollEventBuf::new(0x1, magic);
        lx.dispatch_syscall(LinuxSyscall::EpollCtl {
            epfd,
            op: 1,
            fd: fds[0],
            event: ev.as_ptr(),
        });

        let out = [EpollEventBuf::new(0, 0); 2];
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
            prot: 1,  // PROT_READ
            flags: 2, // MAP_PRIVATE (NOT MAP_ANONYMOUS)
            fd,
            offset: 0,
        });
        assert_eq!(r, ENODEV);
    }

    // ── Fork tests ────────────────────────────────────────────────

    #[test]
    fn test_fork_returns_pid_and_zero() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        let result = lx.dispatch_syscall(LinuxSyscall::Fork);
        assert!(
            result > 0,
            "fork should return child PID to parent, got {result}"
        );
        let child_pid = result as i32;

        let (pid, _child) = lx.pending_fork_child().expect("should have pending child");
        assert_eq!(pid, child_pid);
    }

    #[test]
    fn test_fork_child_exit_resumes_parent() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        let parent_pid = lx.dispatch_syscall(LinuxSyscall::Getpid) as i32;
        let child_pid = lx.dispatch_syscall(LinuxSyscall::Fork) as i32;
        assert!(child_pid > parent_pid);

        // Active process should be the child
        {
            let active = lx.active_process();
            assert_eq!(
                active.dispatch_syscall(LinuxSyscall::Getpid),
                child_pid as i64
            );
        }

        // Child exits
        {
            let active = lx.active_process();
            active.dispatch_syscall(LinuxSyscall::ExitGroup { code: 42 });
        }

        // Active process should be parent again
        {
            let active = lx.active_process();
            assert_eq!(
                active.dispatch_syscall(LinuxSyscall::Getpid),
                parent_pid as i64
            );
        }
    }

    #[test]
    fn test_fork_child_inherits_fds() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        let mut fds = [0i32; 2];
        lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0,
        });

        lx.dispatch_syscall(LinuxSyscall::Fork);

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

        let mut fds = [0i32; 2];
        lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0,
        });
        let read_fd = fds[0];
        let write_fd = fds[1];

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
        assert_eq!(
            child.dispatch_syscall(LinuxSyscall::Getpid),
            child_pid as i64
        );
        assert_eq!(
            child.dispatch_syscall(LinuxSyscall::Getppid),
            parent_pid as i64
        );
        assert_eq!(
            child.dispatch_syscall(LinuxSyscall::Gettid),
            child_pid as i64
        );
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
            assert_eq!(
                child.dispatch_syscall(LinuxSyscall::Getpid),
                child_pid as i64
            );
            let grandchild_pid = child.dispatch_syscall(LinuxSyscall::Fork) as i32;
            assert!(grandchild_pid > child_pid);

            // Grandchild runs
            let gc = child.active_process();
            assert_eq!(
                gc.dispatch_syscall(LinuxSyscall::Getpid),
                grandchild_pid as i64
            );
            assert_eq!(gc.dispatch_syscall(LinuxSyscall::Getppid), child_pid as i64);
            gc.dispatch_syscall(LinuxSyscall::ExitGroup { code: 0 });
        }

        // Child should be active again (grandchild exited)
        {
            let child = lx.active_process();
            assert_eq!(
                child.dispatch_syscall(LinuxSyscall::Getpid),
                child_pid as i64
            );
            child.dispatch_syscall(LinuxSyscall::ExitGroup { code: 0 });
        }

        // Parent should be active again
        let parent = lx.active_process();
        assert_eq!(
            parent.dispatch_syscall(LinuxSyscall::Getpid),
            parent_pid as i64
        );
    }

    #[test]
    fn test_fork_clone_sigchld() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        const SIGCHLD: u64 = 17;
        const CLONE_CHILD_SETTID: u64 = 0x01000000;
        const CLONE_CHILD_CLEARTID: u64 = 0x00200000;

        let r = lx.dispatch_syscall(LinuxSyscall::Clone {
            flags: SIGCHLD | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
            child_stack: 0,
            parent_tid: 0,
            child_tid: 0,
            tls: 0,
        });
        assert!(r > 0, "clone(SIGCHLD) should return child PID, got {r}");

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

        let child = lx.active_process();
        assert_eq!(
            child.dispatch_syscall(LinuxSyscall::Getpid),
            child_pid as i64
        );

        child.dispatch_syscall(LinuxSyscall::ExitGroup { code: 7 });

        let parent = lx.active_process();
        assert_eq!(parent.dispatch_syscall(LinuxSyscall::Getpid), 1);
    }

    #[test]
    fn test_fork_eventfd_shared() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let efd = lx.dispatch_syscall(LinuxSyscall::EventFd2 {
            initval: 0,
            flags: 0,
        }) as i32;
        assert!(efd >= 0);

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

        let mut fds1 = [0i32; 2];
        lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds1.as_mut_ptr() as u64,
            flags: 0,
        });

        lx.dispatch_syscall(LinuxSyscall::Fork);
        {
            let child = lx.active_process();
            child.dispatch_syscall(LinuxSyscall::ExitGroup { code: 0 });
        }

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

    // ── Wait4 tests ───────────────────────────────────────────────

    #[test]
    fn test_wait4_returns_child_pid_and_status() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Fork, child exits with code 42
        let child_pid = lx.dispatch_syscall(LinuxSyscall::Fork) as i32;
        {
            let child = lx.active_process();
            child.dispatch_syscall(LinuxSyscall::ExitGroup { code: 42 });
        }
        // wait4(-1, &wstatus, 0, NULL) — wait for any child
        // (sys_wait4 calls recover_child_state internally)
        let mut wstatus = 0u32;
        let r = lx.dispatch_syscall(LinuxSyscall::Wait4 {
            pid: -1,
            wstatus: &mut wstatus as *mut u32 as u64,
            options: 0,
            rusage: 0,
        });
        assert_eq!(r, child_pid as i64);
        // wstatus: normal exit = (code & 0xFF) << 8
        assert_eq!(wstatus, 42 << 8);
    }

    #[test]
    fn test_wait4_specific_pid() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Fork child 1, exits with code 1
        let pid1 = lx.dispatch_syscall(LinuxSyscall::Fork) as i32;
        {
            let child = lx.active_process();
            child.dispatch_syscall(LinuxSyscall::ExitGroup { code: 1 });
        }

        // Fork child 2, exits with code 2
        // (sys_fork calls recover_child_state internally)
        let pid2 = lx.dispatch_syscall(LinuxSyscall::Fork) as i32;
        {
            let child = lx.active_process();
            child.dispatch_syscall(LinuxSyscall::ExitGroup { code: 2 });
        }

        // Wait for pid2 specifically
        // (sys_wait4 calls recover_child_state internally)
        let mut wstatus = 0u32;
        let r = lx.dispatch_syscall(LinuxSyscall::Wait4 {
            pid: pid2,
            wstatus: &mut wstatus as *mut u32 as u64,
            options: 0,
            rusage: 0,
        });
        assert_eq!(r, pid2 as i64);
        assert_eq!(wstatus, 2 << 8);

        // pid1 should still be in exited_children
        let r = lx.dispatch_syscall(LinuxSyscall::Wait4 {
            pid: pid1,
            wstatus: &mut wstatus as *mut u32 as u64,
            options: 0,
            rusage: 0,
        });
        assert_eq!(r, pid1 as i64);
        assert_eq!(wstatus, 1 << 8);
    }

    #[test]
    fn test_wait4_wnohang_no_children() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // No children at all — ECHILD even with WNOHANG (Linux spec:
        // WNOHANG returns 0 only when children exist but none exited yet)
        let r = lx.dispatch_syscall(LinuxSyscall::Wait4 {
            pid: -1,
            wstatus: 0,
            options: 1, // WNOHANG
            rusage: 0,
        });
        assert_eq!(r, ECHILD);
    }

    #[test]
    fn test_wait4_echild_no_children() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // No children, blocking wait → ECHILD
        let r = lx.dispatch_syscall(LinuxSyscall::Wait4 {
            pid: -1,
            wstatus: 0,
            options: 0,
            rusage: 0,
        });
        assert_eq!(r, ECHILD);
    }

    #[test]
    fn test_wait4_null_wstatus() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let child_pid = lx.dispatch_syscall(LinuxSyscall::Fork) as i32;
        {
            let child = lx.active_process();
            child.dispatch_syscall(LinuxSyscall::ExitGroup { code: 0 });
        }

        // wstatus=0 (null) — should still return child pid without crashing
        // (sys_wait4 calls recover_child_state internally)
        let r = lx.dispatch_syscall(LinuxSyscall::Wait4 {
            pid: -1,
            wstatus: 0,
            options: 0,
            rusage: 0,
        });
        assert_eq!(r, child_pid as i64);
    }

    #[test]
    fn test_wait4_consumes_child() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let _child_pid = lx.dispatch_syscall(LinuxSyscall::Fork) as i32;
        {
            let child = lx.active_process();
            child.dispatch_syscall(LinuxSyscall::ExitGroup { code: 0 });
        }

        // First wait succeeds (sys_wait4 recovers child state internally)
        let r = lx.dispatch_syscall(LinuxSyscall::Wait4 {
            pid: -1,
            wstatus: 0,
            options: 0,
            rusage: 0,
        });
        assert!(r > 0);

        // Second wait — child already consumed → ECHILD
        let r = lx.dispatch_syscall(LinuxSyscall::Wait4 {
            pid: -1,
            wstatus: 0,
            options: 0,
            rusage: 0,
        });
        assert_eq!(r, ECHILD);
    }

    // ── Execve tests ──────────────────────────────────────────────

    #[test]
    fn test_execve_closes_cloexec_fds() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        // Create a pipe — make write end CLOEXEC
        let mut fds = [0i32; 2];
        lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0,
        });
        let read_fd = fds[0];
        let write_fd = fds[1];

        // Set CLOEXEC on write end
        lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: write_fd,
            cmd: 2, // F_SETFD
            arg: FD_CLOEXEC as u64,
        });

        assert!(lx.has_fd(read_fd));
        assert!(lx.has_fd(write_fd));

        lx.close_cloexec_fds();

        // Write end (CLOEXEC) gone, read end + stdio survive
        assert!(lx.has_fd(read_fd));
        assert!(!lx.has_fd(write_fd));
        assert!(lx.has_fd(0));
        assert!(lx.has_fd(1));
        assert!(lx.has_fd(2));
    }

    #[test]
    fn test_execve_cloexec_preserves_pipe_end() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let mut fds = [0i32; 2];
        lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0,
        });
        let read_fd = fds[0];
        let write_fd = fds[1];

        // Write data, then make write end CLOEXEC
        let msg = b"survive";
        lx.dispatch_syscall(LinuxSyscall::Write {
            fd: write_fd,
            buf: msg.as_ptr() as u64,
            count: msg.len() as u64,
        });
        lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: write_fd,
            cmd: 2,
            arg: FD_CLOEXEC as u64,
        });

        lx.close_cloexec_fds();

        // Read end survives, pipe buffer intact
        let mut buf = [0u8; 16];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: read_fd,
            buf: buf.as_mut_ptr() as u64,
            count: 16,
        });
        assert_eq!(r, msg.len() as i64);
        assert_eq!(&buf[..msg.len()], msg);
    }

    #[test]
    fn test_execve_resets_state() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Modify some state
        lx.dispatch_syscall(LinuxSyscall::Getrandom {
            buf: 0,
            buflen: 0,
            flags: 0,
        });

        lx.reset_for_execve();

        // Arena is fresh — brk at base
        let brk_result = lx.dispatch_syscall(LinuxSyscall::Brk { addr: 0 });
        assert!(brk_result >= 0);
    }

    #[test]
    fn test_execve_preserves_pid() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let pid_before = lx.dispatch_syscall(LinuxSyscall::Getpid);
        let ppid_before = lx.dispatch_syscall(LinuxSyscall::Getppid);

        lx.reset_for_execve();

        assert_eq!(lx.dispatch_syscall(LinuxSyscall::Getpid), pid_before);
        assert_eq!(lx.dispatch_syscall(LinuxSyscall::Getppid), ppid_before);
    }

    #[test]
    fn test_execve_preserves_cwd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let mut buf1 = [0u8; 128];
        let r1 = lx.dispatch_syscall(LinuxSyscall::Getcwd {
            buf: buf1.as_mut_ptr() as u64,
            size: 128,
        });

        lx.reset_for_execve();

        let mut buf2 = [0u8; 128];
        let r2 = lx.dispatch_syscall(LinuxSyscall::Getcwd {
            buf: buf2.as_mut_ptr() as u64,
            size: 128,
        });

        assert_eq!(r1, r2);
        assert_eq!(buf1, buf2);
    }

    #[test]
    fn test_execve_bad_path() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        let pid_before = lx.dispatch_syscall(LinuxSyscall::Getpid);

        let mut fds = [0i32; 2];
        lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0,
        });

        // MockBackend.walk always succeeds, but read returns empty
        // bytes (no file_content registered) → ELF parse fails → ENOEXEC
        let path = b"/nonexistent\0";
        let argv: [u64; 1] = [0];
        let envp: [u64; 1] = [0];
        let r = lx.dispatch_syscall(LinuxSyscall::Execve {
            path: path.as_ptr() as u64,
            argv: argv.as_ptr() as u64,
            envp: envp.as_ptr() as u64,
        });
        assert_eq!(r, ENOEXEC);

        // State unchanged
        assert_eq!(lx.dispatch_syscall(LinuxSyscall::Getpid), pid_before);
        assert!(lx.has_fd(0));
        assert!(lx.has_fd(fds[0]));
        assert!(lx.has_fd(fds[1]));
        assert!(lx.pending_execve().is_none());
    }

    #[test]
    fn test_execve_null_path() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let r = lx.dispatch_syscall(LinuxSyscall::Execve {
            path: 0,
            argv: 0,
            envp: 0,
        });
        assert_eq!(r, EFAULT);
    }

    #[test]
    fn test_execve_argv_envp_reading() {
        let s1 = b"hello\0";
        let s2 = b"world\0";
        let ptrs: [u64; 3] = [
            s1.as_ptr() as u64,
            s2.as_ptr() as u64,
            0, // null terminator
        ];

        let result = read_string_array(ptrs.as_ptr() as u64, 256);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "hello");
        assert_eq!(result[1], "world");

        // Null ptr → empty vec
        let empty = read_string_array(0, 256);
        assert!(empty.is_empty());
    }

    #[test]
    fn test_execve_pending_result() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        assert!(lx.pending_execve().is_none());

        // Call apply_execve with synthetic LoadResult
        let load_result = elf_loader::LoadResult {
            entry_point: 0x400000,
            auxv: alloc::vec![(6, 4096)], // AT_PAGESZ
            exe_base: 0x400000,
            interp_base: 0,
        };
        let argv = alloc::vec![alloc::string::String::from("/bin/test")];
        let envp = alloc::vec![alloc::string::String::from("PATH=/usr/bin")];

        lx.apply_execve(&load_result, &argv, &envp);

        let result = lx.pending_execve().unwrap();
        assert_eq!(result.entry_point, 0x400000);
        assert!(result.stack_pointer > 0);

        // Consumed
        assert!(lx.pending_execve().is_none());
    }

    #[test]
    fn test_execve_vm_backend_returns_enosys() {
        let mock = VmMockBackend::new(1024);
        let mut lx = Linuxulator::with_arena(mock, 64 * 1024);

        let path = b"/bin/test\0";
        let r = lx.dispatch_syscall(LinuxSyscall::Execve {
            path: path.as_ptr() as u64,
            argv: 0,
            envp: 0,
        });
        assert_eq!(r, ENOSYS);
    }

    #[test]
    fn test_execve_on_fork_child() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        let child_pid = lx.dispatch_syscall(LinuxSyscall::Fork) as i32;
        assert!(child_pid > 0);

        let child = lx.active_process();
        assert_eq!(
            child.dispatch_syscall(LinuxSyscall::Getpid),
            child_pid as i64
        );

        // Child tries execve — fails (MockBackend) but mechanism works
        let path = b"/bin/test\0";
        let r = child.dispatch_syscall(LinuxSyscall::Execve {
            path: path.as_ptr() as u64,
            argv: 0,
            envp: 0,
        });
        assert_eq!(r, ENOEXEC);

        // PID unchanged after failed execve
        assert_eq!(
            child.dispatch_syscall(LinuxSyscall::Getpid),
            child_pid as i64
        );
    }

    #[test]
    fn test_mprotect_sub_range() {
        let mock = VmMockBackend::new(1024);
        let mut lx = Linuxulator::with_arena(mock, 256 * 1024);

        // mmap 4 pages
        let addr = lx.dispatch_syscall(LinuxSyscall::Mmap {
            addr: 0,
            len: PAGE_SIZE as u64 * 4,
            prot: 3,     // PROT_READ | PROT_WRITE
            flags: 0x22, // MAP_PRIVATE | MAP_ANONYMOUS
            fd: -1,
            offset: 0,
        });
        assert!(addr > 0);

        // mprotect middle 2 pages to PROT_READ
        let r = lx.dispatch_syscall(LinuxSyscall::Mprotect {
            addr: addr as u64 + PAGE_SIZE as u64,
            len: PAGE_SIZE as u64 * 2,
            prot: 1, // PROT_READ
        });
        assert_eq!(r, 0);
    }

    #[test]
    fn test_munmap_sub_range() {
        let mock = VmMockBackend::new(1024);
        let mut lx = Linuxulator::with_arena(mock, 256 * 1024);

        // mmap 4 pages
        let addr = lx.dispatch_syscall(LinuxSyscall::Mmap {
            addr: 0,
            len: PAGE_SIZE as u64 * 4,
            prot: 3,
            flags: 0x22,
            fd: -1,
            offset: 0,
        });
        assert!(addr > 0);

        // munmap middle 2 pages
        let r = lx.dispatch_syscall(LinuxSyscall::Munmap {
            addr: addr as u64 + PAGE_SIZE as u64,
            len: PAGE_SIZE as u64 * 2,
        });
        assert_eq!(r, 0);
    }

    // ── Signal state tests ──────────────────────────────────────────

    /// Build a sigaction byte buffer with the given handler, flags, and mask.
    /// Offsets match the kernel struct layout for the current architecture.
    fn make_sigaction(handler: u64, flags: u64, mask: u64) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&handler.to_ne_bytes());
        buf[8..16].copy_from_slice(&flags.to_ne_bytes());
        #[cfg(target_arch = "x86_64")]
        buf[24..32].copy_from_slice(&mask.to_ne_bytes());
        #[cfg(not(target_arch = "x86_64"))]
        buf[16..24].copy_from_slice(&mask.to_ne_bytes());
        buf
    }

    /// Read the handler field from a sigaction byte buffer.
    fn read_handler(buf: &[u8; 32]) -> u64 {
        u64::from_ne_bytes(buf[0..8].try_into().unwrap())
    }

    /// Read the flags field from a sigaction byte buffer.
    fn read_flags(buf: &[u8; 32]) -> u64 {
        u64::from_ne_bytes(buf[8..16].try_into().unwrap())
    }

    #[test]
    fn test_sigaction_set_and_get() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Set handler=0x400000, flags=SA_SIGINFO (0x04000000), mask=0x0000FFFF for SIGUSR1 (10)
        let act = make_sigaction(0x400000, 0x04000000, 0x0000_FFFF);
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: act.as_ptr() as u64,
            oldact: 0,
            sigsetsize: 8,
        });
        assert_eq!(r, 0);

        // Read back via oldact
        let mut oldact = [0u8; 32];
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: 0,
            oldact: oldact.as_mut_ptr() as u64,
            sigsetsize: 8,
        });
        assert_eq!(r, 0);
        assert_eq!(read_handler(&oldact), 0x400000);
        assert_eq!(read_flags(&oldact), 0x04000000);
    }

    #[test]
    fn test_sigaction_reject_sigkill() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let act = make_sigaction(0x400000, 0, 0);
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: SIGKILL as i32,
            act: act.as_ptr() as u64,
            oldact: 0,
            sigsetsize: 8,
        });
        assert_eq!(r, EINVAL);
    }

    #[test]
    fn test_sigaction_reject_sigstop() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let act = make_sigaction(0x400000, 0, 0);
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: SIGSTOP as i32,
            act: act.as_ptr() as u64,
            oldact: 0,
            sigsetsize: 8,
        });
        assert_eq!(r, EINVAL);
    }

    #[test]
    fn test_sigaction_null_act_reads_only() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Set handler to 0xBEEF for SIGUSR1 (10)
        let act = make_sigaction(0xBEEF, 0, 0);
        lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: act.as_ptr() as u64,
            oldact: 0,
            sigsetsize: 8,
        });

        // Read with act=0 (null) — handler should be unchanged
        let mut oldact = [0u8; 32];
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: 0,
            oldact: oldact.as_mut_ptr() as u64,
            sigsetsize: 8,
        });
        assert_eq!(r, 0);
        assert_eq!(read_handler(&oldact), 0xBEEF);

        // Confirm handler still 0xBEEF after the read-only call
        let mut verify = [0u8; 32];
        lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: 0,
            oldact: verify.as_mut_ptr() as u64,
            sigsetsize: 8,
        });
        assert_eq!(read_handler(&verify), 0xBEEF);
    }

    #[test]
    fn test_sigaction_bad_sigsetsize() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let act = make_sigaction(0x400000, 0, 0);
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: act.as_ptr() as u64,
            oldact: 0,
            sigsetsize: 4, // invalid — must be 8
        });
        assert_eq!(r, EINVAL);
    }

    #[test]
    fn test_sigaction_invalid_signum() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let act = make_sigaction(0x400000, 0, 0);

        // signum 0 is invalid
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 0,
            act: act.as_ptr() as u64,
            oldact: 0,
            sigsetsize: 8,
        });
        assert_eq!(r, EINVAL);

        // signum 65 is out of range
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 65,
            act: act.as_ptr() as u64,
            oldact: 0,
            sigsetsize: 8,
        });
        assert_eq!(r, EINVAL);
    }

    #[test]
    fn test_sigprocmask_block() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Capture old mask — should be 0
        let mut oldset: u64 = 0xDEAD;
        let set: u64 = 1u64 << 9; // bit 9 = signal 10 (SIGUSR1)
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_BLOCK,
            set: &set as *const u64 as u64,
            oldset: &mut oldset as *mut u64 as u64,
            sigsetsize: 8,
        });
        assert_eq!(r, 0);
        assert_eq!(oldset, 0, "initial mask should be 0");

        // Verify new mask has bit 9 set
        let mut current: u64 = 0;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_BLOCK,
            set: 0, // null set — no change
            oldset: &mut current as *mut u64 as u64,
            sigsetsize: 8,
        });
        assert_ne!(
            current & (1u64 << 9),
            0,
            "bit 9 should be set after SIG_BLOCK"
        );
    }

    #[test]
    fn test_sigprocmask_unblock() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Set mask to bits 9 + 10 (signals 10 and 11)
        let set: u64 = (1u64 << 9) | (1u64 << 10);
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: &set as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });

        // Unblock bit 9 only
        let unblock: u64 = 1u64 << 9;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_UNBLOCK,
            set: &unblock as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });

        // Verify only bit 10 remains
        let mut current: u64 = 0;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_BLOCK,
            set: 0,
            oldset: &mut current as *mut u64 as u64,
            sigsetsize: 8,
        });
        assert_eq!(current & (1u64 << 9), 0, "bit 9 should be unblocked");
        assert_ne!(current & (1u64 << 10), 0, "bit 10 should still be blocked");
    }

    #[test]
    fn test_sigprocmask_setmask() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Set mask to 0xDEADBEEF — SIGKILL (bit 8) and SIGSTOP (bit 18) must be cleared
        let set: u64 = 0xDEAD_BEEF;
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: &set as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });
        assert_eq!(r, 0);

        let mut current: u64 = 0;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_BLOCK,
            set: 0,
            oldset: &mut current as *mut u64 as u64,
            sigsetsize: 8,
        });
        assert_eq!(
            current & (1u64 << (SIGKILL - 1)),
            0,
            "SIGKILL bit must be 0"
        );
        assert_eq!(
            current & (1u64 << (SIGSTOP - 1)),
            0,
            "SIGSTOP bit must be 0"
        );
    }

    #[test]
    fn test_sigprocmask_cannot_block_sigkill() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Attempt to block all signals including SIGKILL and SIGSTOP
        let set: u64 = u64::MAX;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: &set as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });

        let mut current: u64 = 0;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_BLOCK,
            set: 0,
            oldset: &mut current as *mut u64 as u64,
            sigsetsize: 8,
        });
        assert_eq!(
            current & (1u64 << 8),
            0,
            "SIGKILL (bit 8) must never be blocked"
        );
        assert_eq!(
            current & (1u64 << 18),
            0,
            "SIGSTOP (bit 18) must never be blocked"
        );
    }

    #[test]
    fn test_sigprocmask_bad_sigsetsize() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let set: u64 = 0;
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_BLOCK,
            set: &set as *const u64 as u64,
            oldset: 0,
            sigsetsize: 16, // invalid — must be 8
        });
        assert_eq!(r, EINVAL);
    }

    #[test]
    fn test_sigprocmask_invalid_how() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let set: u64 = 1;
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: 99, // invalid
            set: &set as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });
        assert_eq!(r, EINVAL);
    }

    #[test]
    fn test_fork_inherits_signal_state() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Set a handler and mask on the parent
        let act = make_sigaction(0x600000, 0x04000000, 0x00FF);
        lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: act.as_ptr() as u64,
            oldact: 0,
            sigsetsize: 8,
        });
        let set: u64 = 1u64 << 9;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: &set as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });

        // Fork — active_process() is now the child
        lx.dispatch_syscall(LinuxSyscall::Fork);
        let child = lx.active_process();

        // Child should have inherited the handler
        let mut child_oldact = [0u8; 32];
        let r = child.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: 0,
            oldact: child_oldact.as_mut_ptr() as u64,
            sigsetsize: 8,
        });
        assert_eq!(r, 0);
        assert_eq!(read_handler(&child_oldact), 0x600000);
        assert_eq!(read_flags(&child_oldact), 0x04000000);

        // Child should have inherited the mask
        let mut child_mask: u64 = 0;
        child.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_BLOCK,
            set: 0,
            oldset: &mut child_mask as *mut u64 as u64,
            sigsetsize: 8,
        });
        assert_eq!(child_mask, set);
    }

    #[test]
    fn test_execve_resets_handlers_preserves_mask() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Set handler for SIGUSR1 (10)
        let act = make_sigaction(0x700000, 0, 0);
        lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: act.as_ptr() as u64,
            oldact: 0,
            sigsetsize: 8,
        });

        // Set a non-zero signal mask
        let set: u64 = (1u64 << 2) | (1u64 << 3); // SIGQUIT + SIGILL bits
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: &set as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });

        // Simulate execve by calling reset_for_execve directly
        lx.reset_for_execve();

        // Handler should be reset to SIG_DFL (0)
        let mut oldact = [0u8; 32];
        lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: 0,
            oldact: oldact.as_mut_ptr() as u64,
            sigsetsize: 8,
        });
        assert_eq!(
            read_handler(&oldact),
            SIG_DFL,
            "handler must be reset to SIG_DFL after execve"
        );

        // Mask should be preserved
        let mut current_mask: u64 = 0;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_BLOCK,
            set: 0,
            oldset: &mut current_mask as *mut u64 as u64,
            sigsetsize: 8,
        });
        assert_eq!(
            current_mask, set,
            "signal mask must be preserved across execve"
        );
    }

    // ── Signal delivery tests ───────────────────────────────────────────

    #[test]
    fn test_kill_self_terminate() {
        // kill(1, 10) — SIGUSR1 with default action Terminate → process exits.
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let r = lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        assert_eq!(r, 0);
        assert!(
            lx.exited(),
            "SIGUSR1 with SIG_DFL should terminate the process"
        );
    }

    #[test]
    fn test_kill_sigchld_default_ignored() {
        // kill(1, 17) — SIGCHLD with default action Ignore → process NOT exited.
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let r = lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 17 });
        assert_eq!(r, 0);
        assert!(
            !lx.exited(),
            "SIGCHLD with SIG_DFL should be ignored, not terminate"
        );
    }

    #[test]
    fn test_kill_sig_ign() {
        // Install SIG_IGN for sig 10, then kill(1, 10) → NOT exited.
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let act = make_sigaction(SIG_IGN, 0, 0);
        lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: act.as_ptr() as u64,
            oldact: 0,
            sigsetsize: 8,
        });
        let r = lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        assert_eq!(r, 0);
        assert!(!lx.exited(), "SIG_IGN should prevent termination");
    }

    #[test]
    fn test_kill_blocked_stays_pending() {
        // Block sig 10, send it → not exited; unblock → exited.
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Block SIGUSR1 (signal 10 → bit 9 in the 64-bit mask).
        let mask: u64 = 1u64 << 9;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: &mask as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });

        // Send signal while blocked.
        let r = lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        assert_eq!(r, 0);
        assert!(!lx.exited(), "blocked signal should not terminate yet");

        // Unblock — pending signal should fire immediately (deliver_pending_signals
        // runs at the end of dispatch_syscall).
        let empty: u64 = 0;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: &empty as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });
        assert!(
            lx.exited(),
            "unblocking should deliver pending SIGUSR1 and terminate"
        );
    }

    #[test]
    fn test_kill_invalid_sig() {
        // kill(1, 65) — signal number out of range → EINVAL.
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let r = lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 65 });
        assert_eq!(r, EINVAL);
        assert!(!lx.exited());
    }

    #[test]
    fn test_kill_null_signal() {
        // kill(1, 0) — null signal, existence check only → 0, NOT exited.
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let r = lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 0 });
        assert_eq!(r, 0);
        assert!(!lx.exited(), "null signal must not terminate the process");
    }

    #[test]
    fn test_kill_unknown_pid_returns_esrch() {
        // kill(999, 10) — PID not in process table → ESRCH.
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let r = lx.dispatch_syscall(LinuxSyscall::Kill { pid: 999, sig: 10 });
        assert_eq!(r, ESRCH);
        assert!(!lx.exited());
    }

    #[test]
    fn test_tgkill_self() {
        // tgkill(1, 1, 10) — send SIGUSR1 to self → exited.
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let r = lx.dispatch_syscall(LinuxSyscall::Tgkill {
            tgid: 1,
            tid: 1,
            sig: 10,
        });
        assert_eq!(r, 0);
        assert!(lx.exited(), "tgkill to self with SIGUSR1 should terminate");
    }

    #[test]
    fn test_tgkill_invalid_tgid_einval() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // tgid <= 0 must return EINVAL per tgkill(2).
        let r1 = lx.dispatch_syscall(LinuxSyscall::Tgkill {
            tgid: -1,
            tid: 1,
            sig: 10,
        });
        assert_eq!(r1, EINVAL, "tgkill(-1, 1, sig) must return EINVAL");
        let r2 = lx.dispatch_syscall(LinuxSyscall::Tgkill {
            tgid: 0,
            tid: 1,
            sig: 10,
        });
        assert_eq!(r2, EINVAL, "tgkill(0, 1, sig) must return EINVAL");
        assert!(!lx.exited());
    }

    #[test]
    fn test_sigchld_on_child_exit() {
        // Fork a child, child exits → parent receives SIGCHLD (default=Ignore)
        // → parent NOT exited.
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.dispatch_syscall(LinuxSyscall::Fork);
        {
            let child = lx.active_process();
            child.dispatch_syscall(LinuxSyscall::ExitGroup { code: 0 });
        }
        // active_process() triggers recover_child_state which queues SIGCHLD.
        let _ = lx.active_process();

        // Dispatch a no-op syscall to trigger deliver_pending_signals,
        // which must apply SIGCHLD's default Ignore disposition.
        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 0 });

        assert!(
            !lx.exited(),
            "SIGCHLD default=Ignore must not terminate parent after delivery"
        );
    }

    #[test]
    fn test_kill_custom_handler_reported() {
        // Install custom handler 0x400000 for sig 10, kill → pending_handler_signal == Some(10).
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let act = make_sigaction(0x400000, 0, 0);
        lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: act.as_ptr() as u64,
            oldact: 0,
            sigsetsize: 8,
        });
        let r = lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        assert_eq!(r, 0);
        assert!(
            !lx.exited(),
            "custom handler should not terminate the process"
        );
        assert_eq!(
            lx.pending_handler_signal(),
            Some(10),
            "custom handler signal must be reported via pending_handler_signal"
        );
    }

    #[test]
    fn test_sigkill_bypasses_mask() {
        // Block all signals, then kill(1, 9) — SIGKILL always terminates.
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Set mask to all-ones (block everything, though SIGKILL cannot be masked).
        let mask: u64 = u64::MAX;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: &mask as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });

        let r = lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 9 });
        assert_eq!(r, 0);
        assert!(
            lx.exited(),
            "SIGKILL must terminate even when all signals are blocked"
        );
    }

    #[test]
    fn test_kill_process_group_enosys() {
        // kill(-1, 10) and kill(-2, 10) — negative PID (process group) → ENOSYS.
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let r1 = lx.dispatch_syscall(LinuxSyscall::Kill { pid: -1, sig: 10 });
        assert_eq!(r1, ENOSYS, "kill(-1, sig) should return ENOSYS");
        let r2 = lx.dispatch_syscall(LinuxSyscall::Kill { pid: -2, sig: 10 });
        assert_eq!(r2, ENOSYS, "kill(-2, sig) should return ENOSYS");
        assert!(!lx.exited());
    }

    #[test]
    fn test_fork_clears_pending_signals() {
        // Block sig 10, send kill to queue it pending, fork → child inherits
        // mask (signal still blocked in child). Unblock in child → child exits.
        // Parent remains not exited because signal was only queued to parent.
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Block SIGUSR1 in parent so the kill queues rather than terminates.
        let mask: u64 = 1u64 << 9;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: &mask as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });

        // Queue SIGUSR1 to parent.
        let r = lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        assert_eq!(r, 0);
        assert!(
            !lx.exited(),
            "signal blocked in parent, should not exit yet"
        );

        // Fork — child inherits mask (SIGUSR1 still blocked). Child should NOT
        // have inherited the pending signal (pending signals are not inherited
        // across fork per POSIX).
        lx.dispatch_syscall(LinuxSyscall::Fork);
        {
            let child = lx.active_process();
            // Unblock SIGUSR1 in child. Because pending signals are cleared on
            // fork, unblocking should not deliver anything.
            let empty: u64 = 0;
            child.dispatch_syscall(LinuxSyscall::RtSigprocmask {
                how: SIG_SETMASK,
                set: &empty as *const u64 as u64,
                oldset: 0,
                sigsetsize: 8,
            });
            assert!(
                !child.exited(),
                "child must not exit — pending signals cleared on fork"
            );
        }
    }

    // ── Nanosleep tests ───────────────────────────────────────────

    #[test]
    fn test_nanosleep_advances_clock() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Get initial monotonic time
        let mut ts1 = [0u8; 16];
        lx.dispatch_syscall(LinuxSyscall::ClockGettime {
            clockid: 1, // CLOCK_MONOTONIC
            tp: ts1.as_mut_ptr() as u64,
        });
        let ns1 = u64::from_le_bytes(ts1[0..8].try_into().unwrap()) * 1_000_000_000
            + u64::from_le_bytes(ts1[8..16].try_into().unwrap());

        // Sleep for 1 second
        let req = [0u8; 16];
        let mut req_buf = req;
        req_buf[0..8].copy_from_slice(&1i64.to_le_bytes()); // tv_sec = 1
        let r = lx.dispatch_syscall(LinuxSyscall::Nanosleep {
            req: req_buf.as_ptr() as u64,
            rem: 0,
        });
        assert_eq!(r, 0);

        // Get time again — should have advanced by ~1s
        let mut ts2 = [0u8; 16];
        lx.dispatch_syscall(LinuxSyscall::ClockGettime {
            clockid: 1,
            tp: ts2.as_mut_ptr() as u64,
        });
        let ns2 = u64::from_le_bytes(ts2[0..8].try_into().unwrap()) * 1_000_000_000
            + u64::from_le_bytes(ts2[8..16].try_into().unwrap());

        // Clock should have advanced by at least 1s (1_000_000_000 ns)
        // Plus 2ms from the two clock_gettime calls
        assert!(ns2 - ns1 >= 1_000_000_000);
    }

    #[test]
    fn test_nanosleep_invalid_args() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Negative tv_sec
        let mut req = [0u8; 16];
        req[0..8].copy_from_slice(&(-1i64).to_le_bytes());
        let r = lx.dispatch_syscall(LinuxSyscall::Nanosleep {
            req: req.as_ptr() as u64,
            rem: 0,
        });
        assert_eq!(r, EINVAL);

        // tv_nsec >= 1_000_000_000
        let mut req2 = [0u8; 16];
        req2[8..16].copy_from_slice(&1_000_000_000i64.to_le_bytes());
        let r = lx.dispatch_syscall(LinuxSyscall::Nanosleep {
            req: req2.as_ptr() as u64,
            rem: 0,
        });
        assert_eq!(r, EINVAL);

        // Null pointer
        let r = lx.dispatch_syscall(LinuxSyscall::Nanosleep { req: 0, rem: 0 });
        assert_eq!(r, EFAULT);
    }

    #[test]
    fn test_clock_nanosleep_invalid_clock() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let mut req = [0u8; 16];
        req[0..8].copy_from_slice(&0i64.to_le_bytes());
        let r = lx.dispatch_syscall(LinuxSyscall::ClockNanosleep {
            clockid: 99, // invalid
            flags: 0,
            req: req.as_ptr() as u64,
            rem: 0,
        });
        assert_eq!(r, EINVAL);
    }

    // ── Prctl tests ───────────────────────────────────────────────

    #[test]
    fn test_prctl_set_and_get_name() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let name = b"myprocess\0\0\0\0\0\0\0";
        let r = lx.dispatch_syscall(LinuxSyscall::Prctl {
            option: 15, // PR_SET_NAME
            arg2: name.as_ptr() as u64,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        });
        assert_eq!(r, 0);

        let mut buf = [0u8; 16];
        let r = lx.dispatch_syscall(LinuxSyscall::Prctl {
            option: 16, // PR_GET_NAME
            arg2: buf.as_mut_ptr() as u64,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        });
        assert_eq!(r, 0);
        assert_eq!(&buf[..9], b"myprocess");
        assert_eq!(buf[9], 0); // null terminated
    }

    #[test]
    fn test_prctl_unknown_option_succeeds() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Unknown option → 0 (stub, don't break programs)
        let r = lx.dispatch_syscall(LinuxSyscall::Prctl {
            option: 9999,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        });
        assert_eq!(r, 0);
    }

    // ── SignalFd tests ────────────────────────────────────────────

    #[test]
    fn test_signalfd_create() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let mask: u64 = 1 << 9; // signal 10 (SIGUSR1)
        let fd = lx.dispatch_syscall(LinuxSyscall::SignalFd4 {
            fd: -1,
            mask_ptr: &mask as *const u64 as u64,
            sizemask: 8,
            flags: 0,
        });
        assert!(fd >= 0, "signalfd4 should return a valid fd, got {fd}");
        assert!(lx.has_fd(fd as i32));
    }

    #[test]
    fn test_signalfd_read_pending() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Block SIGUSR1 so it stays pending (not delivered by deliver_pending_signals)
        let mask: u64 = 1 << 9;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: &mask as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });

        // Create signalfd monitoring SIGUSR1
        let sfd = lx.dispatch_syscall(LinuxSyscall::SignalFd4 {
            fd: -1,
            mask_ptr: &mask as *const u64 as u64,
            sizemask: 8,
            flags: 0,
        }) as i32;

        // Queue SIGUSR1
        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });

        // Read from signalfd — should get siginfo with ssi_signo=10
        let mut siginfo = [0u8; 128];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: sfd,
            buf: siginfo.as_mut_ptr() as u64,
            count: 128,
        });
        assert_eq!(r, 128);
        let ssi_signo = u32::from_le_bytes(siginfo[0..4].try_into().unwrap());
        assert_eq!(ssi_signo, 10);
    }

    #[test]
    fn test_signalfd_no_pending_eagain() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let mask: u64 = 1 << 9;
        let sfd = lx.dispatch_syscall(LinuxSyscall::SignalFd4 {
            fd: -1,
            mask_ptr: &mask as *const u64 as u64,
            sizemask: 8,
            flags: 0,
        }) as i32;

        // No pending signals — read should return EAGAIN
        let mut siginfo = [0u8; 128];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: sfd,
            buf: siginfo.as_mut_ptr() as u64,
            count: 128,
        });
        assert_eq!(r, EAGAIN);
    }

    #[test]
    fn test_signalfd_consumes_signal() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Block and queue SIGUSR1
        let mask: u64 = 1 << 9;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: &mask as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });

        let sfd = lx.dispatch_syscall(LinuxSyscall::SignalFd4 {
            fd: -1,
            mask_ptr: &mask as *const u64 as u64,
            sizemask: 8,
            flags: 0,
        }) as i32;

        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });

        // First read consumes the signal
        let mut siginfo = [0u8; 128];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: sfd,
            buf: siginfo.as_mut_ptr() as u64,
            count: 128,
        });
        assert_eq!(r, 128);

        // Second read — signal consumed, should EAGAIN
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: sfd,
            buf: siginfo.as_mut_ptr() as u64,
            count: 128,
        });
        assert_eq!(r, EAGAIN);
    }

    #[test]
    fn test_signalfd_update_mask() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Create signalfd for SIGUSR1
        let mask1: u64 = 1 << 9;
        let sfd = lx.dispatch_syscall(LinuxSyscall::SignalFd4 {
            fd: -1,
            mask_ptr: &mask1 as *const u64 as u64,
            sizemask: 8,
            flags: 0,
        }) as i32;

        // Block both signals and queue SIGUSR2 (signal 12)
        let block_mask: u64 = (1 << 9) | (1 << 11);
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: &block_mask as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });
        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 12 });

        // Read — should EAGAIN (mask only watches SIGUSR1, not SIGUSR2)
        let mut siginfo = [0u8; 128];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: sfd,
            buf: siginfo.as_mut_ptr() as u64,
            count: 128,
        });
        assert_eq!(r, EAGAIN);

        // Update mask to include SIGUSR2
        let mask2: u64 = (1 << 9) | (1 << 11);
        let r = lx.dispatch_syscall(LinuxSyscall::SignalFd4 {
            fd: sfd,
            mask_ptr: &mask2 as *const u64 as u64,
            sizemask: 8,
            flags: 0,
        });
        assert_eq!(r, sfd as i64);

        // Now read should succeed
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: sfd,
            buf: siginfo.as_mut_ptr() as u64,
            count: 128,
        });
        assert_eq!(r, 128);
        let ssi_signo = u32::from_le_bytes(siginfo[0..4].try_into().unwrap());
        assert_eq!(ssi_signo, 12);
    }

    #[test]
    fn test_signalfd_cloexec() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let mask: u64 = 1 << 9;
        let sfd = lx.dispatch_syscall(LinuxSyscall::SignalFd4 {
            fd: -1,
            mask_ptr: &mask as *const u64 as u64,
            sizemask: 8,
            flags: 0x80000, // SFD_CLOEXEC
        }) as i32;

        let flags = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd: sfd,
            cmd: 1, // F_GETFD
            arg: 0,
        });
        assert_eq!(flags, FD_CLOEXEC as i64);
    }

    // ── TimerFd tests ─────────────────────────────────────────────

    #[test]
    fn test_timerfd_create() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let fd = lx.dispatch_syscall(LinuxSyscall::TimerfdCreate {
            clockid: 1, // CLOCK_MONOTONIC
            flags: 0,
        });
        assert!(fd >= 0);
        assert!(lx.has_fd(fd as i32));
    }

    #[test]
    fn test_timerfd_read_disarmed_eagain() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let fd = lx.dispatch_syscall(LinuxSyscall::TimerfdCreate {
            clockid: 1,
            flags: 0,
        }) as i32;
        let mut buf = [0u8; 8];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd,
            buf: buf.as_mut_ptr() as u64,
            count: 8,
        });
        assert_eq!(r, EAGAIN);
    }

    #[test]
    fn test_timerfd_arm_and_expire() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let fd = lx.dispatch_syscall(LinuxSyscall::TimerfdCreate {
            clockid: 1, // CLOCK_MONOTONIC
            flags: 0,
        }) as i32;

        // Arm: expire after 1 second (relative)
        let mut its = [0u8; 32];
        // it_interval = 0 (one-shot)
        // it_value = { tv_sec=1, tv_nsec=0 }
        its[16..24].copy_from_slice(&1i64.to_le_bytes());
        lx.dispatch_syscall(LinuxSyscall::TimerfdSettime {
            fd,
            flags: 0,
            new_value: its.as_ptr() as u64,
            old_value: 0,
        });

        // Advance monotonic clock past 1 second via nanosleep
        let mut sleep_req = [0u8; 16];
        sleep_req[0..8].copy_from_slice(&2i64.to_le_bytes()); // sleep 2 seconds
        lx.dispatch_syscall(LinuxSyscall::Nanosleep {
            req: sleep_req.as_ptr() as u64,
            rem: 0,
        });

        // Read — should return count=1
        let mut buf = [0u8; 8];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd,
            buf: buf.as_mut_ptr() as u64,
            count: 8,
        });
        assert_eq!(r, 8);
        let count = u64::from_le_bytes(buf);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_timerfd_not_yet_expired() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let fd = lx.dispatch_syscall(LinuxSyscall::TimerfdCreate {
            clockid: 1,
            flags: 0,
        }) as i32;

        // Arm: expire after 10 seconds
        let mut its = [0u8; 32];
        its[16..24].copy_from_slice(&10i64.to_le_bytes());
        lx.dispatch_syscall(LinuxSyscall::TimerfdSettime {
            fd,
            flags: 0,
            new_value: its.as_ptr() as u64,
            old_value: 0,
        });

        // Advance clock only 1 second
        let mut sleep_req = [0u8; 16];
        sleep_req[0..8].copy_from_slice(&1i64.to_le_bytes());
        lx.dispatch_syscall(LinuxSyscall::Nanosleep {
            req: sleep_req.as_ptr() as u64,
            rem: 0,
        });

        // Read — not expired yet
        let mut buf = [0u8; 8];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd,
            buf: buf.as_mut_ptr() as u64,
            count: 8,
        });
        assert_eq!(r, EAGAIN);
    }

    #[test]
    fn test_timerfd_repeating() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let fd = lx.dispatch_syscall(LinuxSyscall::TimerfdCreate {
            clockid: 1,
            flags: 0,
        }) as i32;

        // Arm: expire after 1s, repeat every 1s
        let mut its = [0u8; 32];
        its[0..8].copy_from_slice(&1i64.to_le_bytes()); // it_interval.tv_sec = 1
        its[16..24].copy_from_slice(&1i64.to_le_bytes()); // it_value.tv_sec = 1
        lx.dispatch_syscall(LinuxSyscall::TimerfdSettime {
            fd,
            flags: 0,
            new_value: its.as_ptr() as u64,
            old_value: 0,
        });

        // Advance clock 3.5 seconds (should fire 3 times)
        let mut sleep_req = [0u8; 16];
        sleep_req[0..8].copy_from_slice(&3i64.to_le_bytes());
        sleep_req[8..16].copy_from_slice(&500_000_000i64.to_le_bytes());
        lx.dispatch_syscall(LinuxSyscall::Nanosleep {
            req: sleep_req.as_ptr() as u64,
            rem: 0,
        });

        let mut buf = [0u8; 8];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd,
            buf: buf.as_mut_ptr() as u64,
            count: 8,
        });
        assert_eq!(r, 8);
        let count = u64::from_le_bytes(buf);
        assert!(count >= 3, "expected at least 3 expirations, got {count}");
    }

    #[test]
    fn test_timerfd_settime_disarm() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let fd = lx.dispatch_syscall(LinuxSyscall::TimerfdCreate {
            clockid: 1,
            flags: 0,
        }) as i32;

        // Arm
        let mut its = [0u8; 32];
        its[16..24].copy_from_slice(&1i64.to_le_bytes());
        lx.dispatch_syscall(LinuxSyscall::TimerfdSettime {
            fd,
            flags: 0,
            new_value: its.as_ptr() as u64,
            old_value: 0,
        });

        // Disarm (it_value = 0,0)
        let disarm = [0u8; 32];
        lx.dispatch_syscall(LinuxSyscall::TimerfdSettime {
            fd,
            flags: 0,
            new_value: disarm.as_ptr() as u64,
            old_value: 0,
        });

        // Advance clock and read — should EAGAIN
        let mut sleep_req = [0u8; 16];
        sleep_req[0..8].copy_from_slice(&5i64.to_le_bytes());
        lx.dispatch_syscall(LinuxSyscall::Nanosleep {
            req: sleep_req.as_ptr() as u64,
            rem: 0,
        });

        let mut buf = [0u8; 8];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd,
            buf: buf.as_mut_ptr() as u64,
            count: 8,
        });
        assert_eq!(r, EAGAIN);
    }

    #[test]
    fn test_timerfd_cloexec() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        let fd = lx.dispatch_syscall(LinuxSyscall::TimerfdCreate {
            clockid: 1,
            flags: 0x80000, // TFD_CLOEXEC
        }) as i32;

        let flags = lx.dispatch_syscall(LinuxSyscall::Fcntl {
            fd,
            cmd: 1, // F_GETFD
            arg: 0,
        });
        assert_eq!(flags, FD_CLOEXEC as i64);
    }

    // ── Poll tests ────────────────────────────────────────────────

    #[test]
    fn test_poll_returns_ready() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        // struct pollfd { fd: i32, events: i16, revents: i16 }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct PollFd {
            fd: i32,
            events: i16,
            revents: i16,
        }

        let mut fds = [
            PollFd {
                fd: 0,
                events: 1,
                revents: 0,
            }, // POLLIN on stdin
            PollFd {
                fd: 1,
                events: 4,
                revents: 0,
            }, // POLLOUT on stdout
        ];

        let r = lx.dispatch_syscall(LinuxSyscall::Poll {
            fds: fds.as_mut_ptr() as u64,
            nfds: 2,
            timeout: 0,
        });
        assert_eq!(r, 2); // both ready
        assert_eq!(fds[0].revents, 1); // POLLIN
        assert_eq!(fds[1].revents, 4); // POLLOUT
    }

    #[test]
    fn test_poll_invalid_fd_pollnval() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        #[repr(C)]
        #[derive(Clone, Copy)]
        struct PollFd {
            fd: i32,
            events: i16,
            revents: i16,
        }

        let mut fds = [PollFd {
            fd: 999,
            events: 1,
            revents: 0,
        }];

        let r = lx.dispatch_syscall(LinuxSyscall::Poll {
            fds: fds.as_mut_ptr() as u64,
            nfds: 1,
            timeout: 0,
        });
        assert_eq!(r, 1);
        assert_eq!(fds[0].revents, 0x20); // POLLNVAL
    }

    #[test]
    fn test_poll_negative_fd_ignored() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        #[repr(C)]
        #[derive(Clone, Copy)]
        struct PollFd {
            fd: i32,
            events: i16,
            revents: i16,
        }

        let mut fds = [PollFd {
            fd: -1,
            events: 1,
            revents: 0xFF,
        }];

        let r = lx.dispatch_syscall(LinuxSyscall::Poll {
            fds: fds.as_mut_ptr() as u64,
            nfds: 1,
            timeout: 0,
        });
        assert_eq!(r, 0); // negative fd ignored, revents=0
        assert_eq!(fds[0].revents, 0);
    }

    // ── readv / socketpair / getrlimit / umask / ftruncate / renameat ──

    #[test]
    fn test_readv_basic() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        // Create a pipe and write 10 bytes to it.
        let mut pipe_fds = [0i32; 2];
        let r = lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: pipe_fds.as_mut_ptr() as u64,
            flags: 0,
        });
        assert_eq!(r, 0);
        let (rfd, wfd) = (pipe_fds[0], pipe_fds[1]);

        let data = b"helloworld";
        lx.dispatch_syscall(LinuxSyscall::Write {
            fd: wfd,
            buf: data.as_ptr() as u64,
            count: data.len() as u64,
        });

        // readv into two 5-byte buffers.
        let mut buf0 = [0u8; 5];
        let mut buf1 = [0u8; 5];
        let mut iov = [0u8; 32]; // 2 × 16-byte iovec
        iov[0..8].copy_from_slice(&(buf0.as_mut_ptr() as u64).to_le_bytes());
        iov[8..16].copy_from_slice(&5u64.to_le_bytes());
        iov[16..24].copy_from_slice(&(buf1.as_mut_ptr() as u64).to_le_bytes());
        iov[24..32].copy_from_slice(&5u64.to_le_bytes());

        let total = lx.dispatch_syscall(LinuxSyscall::Readv {
            fd: rfd,
            iov: iov.as_ptr() as u64,
            iovcnt: 2,
        });
        assert_eq!(total, 10);
        assert_eq!(&buf0, b"hello");
        assert_eq!(&buf1, b"world");
    }

    #[test]
    fn test_socketpair_creates_two_fds() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let mut sv = [0i32; 2];
        let r = lx.dispatch_syscall(LinuxSyscall::Socketpair {
            domain: 1,    // AF_UNIX
            sock_type: 1, // SOCK_STREAM
            protocol: 0,
            sv: sv.as_mut_ptr() as u64,
        });
        assert_eq!(r, 0);
        let fd0 = sv[0];
        let fd1 = sv[1];
        assert!(fd0 >= 0);
        assert!(fd1 >= 0);
        assert_ne!(fd0, fd1);
        assert!(lx.has_fd(fd0));
        assert!(lx.has_fd(fd1));
    }

    #[test]
    fn test_getrlimit_returns_infinity() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let mut rlim = [0u64; 2]; // { rlim_cur, rlim_max }
        let r = lx.dispatch_syscall(LinuxSyscall::Getrlimit {
            resource: 7, // RLIMIT_NOFILE
            rlim: rlim.as_mut_ptr() as u64,
        });
        assert_eq!(r, 0);
        assert_eq!(rlim[0], u64::MAX); // rlim_cur = RLIM_INFINITY
        assert_eq!(rlim[1], u64::MAX); // rlim_max = RLIM_INFINITY
    }

    #[test]
    fn test_umask_returns_old_and_sets_new() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Default umask is 0o022; first call returns 0o022 and sets 0o077.
        let old = lx.dispatch_syscall(LinuxSyscall::Umask { mask: 0o077 });
        assert_eq!(old, 0o022);

        // Second call returns 0o077 and restores 0o022.
        let prev = lx.dispatch_syscall(LinuxSyscall::Umask { mask: 0o022 });
        assert_eq!(prev, 0o077);
    }

    #[test]
    fn test_ftruncate_stub() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);
        lx.init_stdio().unwrap();

        // Open a regular file to get a File fd.
        let path = b"/data/file.txt\0";
        let fd = lx.dispatch_syscall(LinuxSyscall::Openat {
            dirfd: -100, // AT_FDCWD
            pathname: path.as_ptr() as u64,
            flags: 0,
        });
        assert!(fd >= 0);

        let r = lx.dispatch_syscall(LinuxSyscall::Ftruncate {
            fd: fd as i32,
            length: 42,
        });
        assert_eq!(r, 0); // stub success
    }

    #[test]
    fn test_renameat_returns_erofs() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let old = b"/foo\0";
        let new = b"/bar\0";
        let r = lx.dispatch_syscall(LinuxSyscall::Renameat {
            olddirfd: -100,
            oldpath: old.as_ptr() as u64,
            newdirfd: -100,
            newpath: new.as_ptr() as u64,
        });
        assert_eq!(r, EROFS);
    }

    // ── setup_signal_frame tests ────────────────────────────────────

    /// Helper: install a signal handler with SA_RESTORER set, including the
    /// restorer address at bytes 16..24 of the sigaction buffer (x86_64 layout).
    fn install_handler_with_restorer(
        lx: &mut Linuxulator<MockBackend>,
        signum: i32,
        handler: u64,
        flags: u64,
        mask: u64,
        restorer: u64,
    ) {
        let mut act = make_sigaction(handler, flags, mask);
        // On x86_64, sa_restorer lives at bytes 16..24.
        #[cfg(target_arch = "x86_64")]
        act[16..24].copy_from_slice(&restorer.to_ne_bytes());
        let _ = restorer; // suppress unused warning on non-x86_64
        lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum,
            act: act.as_ptr() as u64,
            oldact: 0,
            sigsetsize: 8,
        });
    }

    /// Read the current signal mask without modifying it.
    fn read_signal_mask(lx: &mut Linuxulator<MockBackend>) -> u64 {
        let mut oldset = [0u8; 8];
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_BLOCK,
            set: 0,
            oldset: oldset.as_mut_ptr() as u64,
            sigsetsize: 8,
        });
        u64::from_ne_bytes(oldset)
    }

    #[test]
    fn test_setup_signal_frame_basic() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER | SA_SIGINFO;

        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, 0, restorer_addr);

        // Send SIGUSR1 (10) to self.
        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        let sig = lx.pending_handler_signal();
        assert_eq!(sig, Some(10));

        // RSP must point into real writable memory (the arena).
        // Place it near the top of the 1 MiB arena so the frame fits below.
        let rsp = (lx.arena_base() + 0x50000) as u64;

        let regs = SavedRegisters {
            r8: 0x08,
            r9: 0x09,
            r10: 0x10,
            r11: 0x11,
            r12: 0x12,
            r13: 0x13,
            r14: 0x14,
            r15: 0x15,
            rdi: 0xD1,
            rsi: 0x51,
            rbp: 0xBB,
            rbx: 0xBB,
            rdx: 0xDD,
            rax: 0xAA,
            rcx: 0xCC,
            rsp,
            rip: 0x1000,
            eflags: 0x202,
        };

        let setup = lx.setup_signal_frame(10, &regs);

        // handler_rip must equal the installed handler address.
        assert_eq!(setup.handler_rip, handler_addr);

        // rdi = signal number.
        assert_eq!(setup.rdi, 10);

        // SA_SIGINFO was set, so rsi (siginfo ptr) and rdx (ucontext ptr) must be non-zero.
        assert_ne!(
            setup.rsi, 0,
            "rsi (siginfo_t pointer) must be non-zero for SA_SIGINFO"
        );
        assert_ne!(
            setup.rdx, 0,
            "rdx (ucontext_t pointer) must be non-zero for SA_SIGINFO"
        );

        // handler_rsp must be ≡ 8 (mod 16) for x86_64 ABI.
        assert_eq!(
            setup.handler_rsp % 16,
            8,
            "handler_rsp must be 8 mod 16 (post-call alignment)"
        );
    }

    #[test]
    fn test_signal_mask_blocks_during_handler() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER | SA_SIGINFO;
        // sa_mask blocks signal 12 (bit 11).
        let sa_mask: u64 = 1u64 << 11;

        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, sa_mask, restorer_addr);

        // Send SIGUSR1 (10).
        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        let sig = lx.pending_handler_signal();
        assert_eq!(sig, Some(10));

        let rsp = (lx.arena_base() + 0x50000) as u64;
        let regs = SavedRegisters {
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rbx: 0,
            rdx: 0,
            rax: 0,
            rcx: 0,
            rsp,
            rip: 0x1000,
            eflags: 0x202,
        };

        let _setup = lx.setup_signal_frame(10, &regs);

        let mask = read_signal_mask(&mut lx);

        // Signal 10 (bit 9) should be blocked (SA_NODEFER not set → auto-block).
        assert_ne!(
            mask & (1u64 << 9),
            0,
            "signal 10 should be blocked during handler (no SA_NODEFER)"
        );

        // Signal 12 (bit 11) should be blocked via sa_mask.
        assert_ne!(
            mask & (1u64 << 11),
            0,
            "signal 12 should be blocked via sa_mask"
        );
    }

    #[test]
    fn test_sa_nodefer() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER | SA_SIGINFO | SA_NODEFER;

        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, 0, restorer_addr);

        // Send SIGUSR1 (10).
        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        let sig = lx.pending_handler_signal();
        assert_eq!(sig, Some(10));

        let rsp = (lx.arena_base() + 0x50000) as u64;
        let regs = SavedRegisters {
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rbx: 0,
            rdx: 0,
            rax: 0,
            rcx: 0,
            rsp,
            rip: 0x1000,
            eflags: 0x202,
        };

        let _setup = lx.setup_signal_frame(10, &regs);

        let mask = read_signal_mask(&mut lx);

        // With SA_NODEFER, signal 10 (bit 9) should NOT be blocked.
        assert_eq!(
            mask & (1u64 << 9),
            0,
            "signal 10 must NOT be blocked when SA_NODEFER is set"
        );
    }

    #[test]
    fn test_sa_resethand() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER | SA_SIGINFO | SA_RESETHAND;

        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, 0, restorer_addr);

        // Send SIGUSR1 (10).
        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        let sig = lx.pending_handler_signal();
        assert_eq!(sig, Some(10));

        let rsp = (lx.arena_base() + 0x50000) as u64;
        let regs = SavedRegisters {
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rbx: 0,
            rdx: 0,
            rax: 0,
            rcx: 0,
            rsp,
            rip: 0x1000,
            eflags: 0x202,
        };

        let _setup = lx.setup_signal_frame(10, &regs);

        // After SA_RESETHAND, the handler should be reset to SIG_DFL.
        let mut oldact = [0u8; 32];
        lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: 0,
            oldact: oldact.as_mut_ptr() as u64,
            sigsetsize: 8,
        });
        assert_eq!(
            read_handler(&oldact),
            SIG_DFL,
            "handler must be reset to SIG_DFL after SA_RESETHAND"
        );
    }

    #[test]
    fn test_sigreturn_restores_registers() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER | SA_SIGINFO;

        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, 0, restorer_addr);

        // Send SIGUSR1 (10).
        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        let sig = lx.pending_handler_signal();
        assert_eq!(sig, Some(10));

        // Place the stack in real writable memory (the arena).
        let rsp = (lx.arena_base() + 0x50000) as u64;

        // Known register values to save and restore.
        let regs = SavedRegisters {
            r8: 0x0808_0808,
            r9: 0x0909_0909,
            r10: 0x1010_1010,
            r11: 0x1111_1111,
            r12: 0x1212_1212,
            r13: 0x1313_1313,
            r14: 0x1414_1414,
            r15: 0x1515_1515,
            rdi: 0xD1D1_D1D1,
            rsi: 0x5151_5151,
            rbp: 0xBBBB_BBBB,
            rbx: 0xBBB0_BBB0,
            rdx: 0xDDDD_DDDD,
            rax: 0xAAAA_AAAA,
            rcx: 0xCCCC_CCCC,
            rsp,
            rip: 0x1000,
            eflags: 0x202,
        };

        let setup = lx.setup_signal_frame(10, &regs);

        // Simulate handler executing `ret` which pops sa_restorer,
        // then sa_restorer does syscall with RSP = handler_rsp + 8.
        let sigreturn_rsp = setup.handler_rsp + 8;

        let _result = lx.dispatch_syscall(LinuxSyscall::RtSigreturn { rsp: sigreturn_rsp });

        let sr = lx.pending_signal_return();
        assert!(
            sr.is_some(),
            "pending_signal_return must be Some after sigreturn"
        );
        let restored = sr.unwrap().regs;

        assert_eq!(restored.r8, 0x0808_0808);
        assert_eq!(restored.r9, 0x0909_0909);
        assert_eq!(restored.r10, 0x1010_1010);
        assert_eq!(restored.r11, 0x1111_1111);
        assert_eq!(restored.r12, 0x1212_1212);
        assert_eq!(restored.r13, 0x1313_1313);
        assert_eq!(restored.r14, 0x1414_1414);
        assert_eq!(restored.r15, 0x1515_1515);
        assert_eq!(restored.rdi, 0xD1D1_D1D1);
        assert_eq!(restored.rsi, 0x5151_5151);
        assert_eq!(restored.rbp, 0xBBBB_BBBB);
        assert_eq!(restored.rbx, 0xBBB0_BBB0);
        assert_eq!(restored.rdx, 0xDDDD_DDDD);
        assert_eq!(restored.rax, 0xAAAA_AAAA);
        assert_eq!(restored.rcx, 0xCCCC_CCCC);
        assert_eq!(restored.rsp, rsp);
        assert_eq!(restored.rip, 0x1000);
        assert_eq!(restored.eflags, 0x202);
    }

    #[test]
    fn test_sigreturn_restores_signal_mask() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER | SA_SIGINFO;
        // sa_mask blocks signal 14 (bit 13).
        let sa_mask: u64 = 1u64 << 13;

        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, sa_mask, restorer_addr);

        // Pre-block signals 12 and 13 (bits 11 and 12).
        let pre_block: u64 = (1u64 << 11) | (1u64 << 12);
        let pre_block_bytes = pre_block.to_ne_bytes();
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: pre_block_bytes.as_ptr() as u64,
            oldset: 0,
            sigsetsize: 8,
        });

        // Verify pre-block mask.
        let mask_before_kill = read_signal_mask(&mut lx);
        assert_ne!(
            mask_before_kill & (1u64 << 11),
            0,
            "signal 12 should be blocked"
        );
        assert_ne!(
            mask_before_kill & (1u64 << 12),
            0,
            "signal 13 should be blocked"
        );

        // Send SIGUSR1 (10).
        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        let sig = lx.pending_handler_signal();
        assert_eq!(sig, Some(10));

        let rsp = (lx.arena_base() + 0x50000) as u64;
        let regs = SavedRegisters {
            rsp,
            ..SavedRegisters::default()
        };

        let setup = lx.setup_signal_frame(10, &regs);

        // After setup_signal_frame, mask should have 10+12+13+14 blocked.
        let mask_during = read_signal_mask(&mut lx);
        assert_ne!(
            mask_during & (1u64 << 9),
            0,
            "signal 10 blocked during handler"
        );
        assert_ne!(mask_during & (1u64 << 11), 0, "signal 12 still blocked");
        assert_ne!(mask_during & (1u64 << 12), 0, "signal 13 still blocked");
        assert_ne!(
            mask_during & (1u64 << 13),
            0,
            "signal 14 blocked via sa_mask"
        );

        // sigreturn restores the mask.
        let sigreturn_rsp = setup.handler_rsp + 8;
        lx.dispatch_syscall(LinuxSyscall::RtSigreturn { rsp: sigreturn_rsp });
        let _ = lx.pending_signal_return(); // consume

        // After sigreturn, mask should be restored to just 12+13.
        let mask_after = read_signal_mask(&mut lx);
        assert_eq!(
            mask_after & (1u64 << 9),
            0,
            "signal 10 must be unblocked after sigreturn"
        );
        assert_ne!(
            mask_after & (1u64 << 11),
            0,
            "signal 12 must remain blocked (was pre-blocked)"
        );
        assert_ne!(
            mask_after & (1u64 << 12),
            0,
            "signal 13 must remain blocked (was pre-blocked)"
        );
        assert_eq!(
            mask_after & (1u64 << 13),
            0,
            "signal 14 must be unblocked (was only in sa_mask)"
        );
    }

    #[test]
    fn test_sigreturn_delivers_unblocked() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER | SA_SIGINFO;

        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, 0, restorer_addr);

        // First kill: triggers signal 10, delivered to handler.
        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        let sig = lx.pending_handler_signal();
        assert_eq!(sig, Some(10));

        let rsp = (lx.arena_base() + 0x50000) as u64;
        let regs = SavedRegisters {
            rsp,
            ..SavedRegisters::default()
        };

        let setup = lx.setup_signal_frame(10, &regs);

        // Signal 10 is now blocked during the handler (no SA_NODEFER).
        let mask_during = read_signal_mask(&mut lx);
        assert_ne!(
            mask_during & (1u64 << 9),
            0,
            "signal 10 blocked during handler"
        );

        // Second kill: signal 10 queued but blocked.
        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        // Should NOT fire handler because signal 10 is blocked.
        assert!(
            lx.pending_handler_signal().is_none(),
            "signal 10 should be queued but not delivered while blocked"
        );

        // sigreturn restores mask (signal 10 unblocked).
        // deliver_pending_signals runs at end of dispatch_syscall,
        // so the queued signal 10 should fire.
        let sigreturn_rsp = setup.handler_rsp + 8;
        lx.dispatch_syscall(LinuxSyscall::RtSigreturn { rsp: sigreturn_rsp });

        // Consume the signal return (restored regs).
        let sr = lx.pending_signal_return();
        assert!(sr.is_some(), "pending_signal_return must be set");

        // The previously-blocked signal 10 should now be delivered.
        let sig2 = lx.pending_handler_signal();
        assert_eq!(
            sig2,
            Some(10),
            "signal 10 must be delivered after sigreturn unblocks it"
        );
    }

    // ── sigaltstack tests ───────────────────────────────────────────

    /// Helper: write a stack_t buffer (ss_sp u64, ss_flags i32, _pad i32, ss_size u64).
    fn make_stack_t(sp: u64, flags: i32, size: u64) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(&sp.to_ne_bytes());
        buf[8..12].copy_from_slice(&flags.to_ne_bytes());
        // bytes 12..16 are padding — leave as zero
        buf[16..24].copy_from_slice(&size.to_ne_bytes());
        buf
    }

    #[test]
    fn test_sigaltstack_set_and_get() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Configure alt stack: sp=0x60000, size=8192, flags=0.
        let ss = make_stack_t(0x60000, 0, 8192);
        let r = lx.dispatch_syscall(LinuxSyscall::Sigaltstack {
            ss: ss.as_ptr() as u64,
            old_ss: 0,
        });
        assert_eq!(r, 0, "sigaltstack set should succeed");

        // Read back via old_ss.
        let mut old = [0u8; 24];
        let r = lx.dispatch_syscall(LinuxSyscall::Sigaltstack {
            ss: 0,
            old_ss: old.as_mut_ptr() as u64,
        });
        assert_eq!(r, 0, "sigaltstack get should succeed");

        let sp_out = u64::from_ne_bytes(old[0..8].try_into().unwrap());
        let flags_out = i32::from_ne_bytes(old[8..12].try_into().unwrap());
        let size_out = u64::from_ne_bytes(old[16..24].try_into().unwrap());

        assert_eq!(sp_out, 0x60000, "sp should round-trip");
        assert_eq!(flags_out, 0, "flags should round-trip");
        assert_eq!(size_out, 8192, "size should round-trip");
    }

    #[test]
    fn test_sigaltstack_disable() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // First configure a valid alt stack.
        let ss = make_stack_t(0x70000, 0, 8192);
        let r = lx.dispatch_syscall(LinuxSyscall::Sigaltstack {
            ss: ss.as_ptr() as u64,
            old_ss: 0,
        });
        assert_eq!(r, 0);

        // Now disable it.
        let ss_disable = make_stack_t(0, SS_DISABLE, 0);
        let r = lx.dispatch_syscall(LinuxSyscall::Sigaltstack {
            ss: ss_disable.as_ptr() as u64,
            old_ss: 0,
        });
        assert_eq!(r, 0, "SS_DISABLE should succeed");

        // Read back and verify flags has SS_DISABLE.
        let mut old = [0u8; 24];
        lx.dispatch_syscall(LinuxSyscall::Sigaltstack {
            ss: 0,
            old_ss: old.as_mut_ptr() as u64,
        });
        let flags_out = i32::from_ne_bytes(old[8..12].try_into().unwrap());
        assert_ne!(
            flags_out & SS_DISABLE,
            0,
            "flags should have SS_DISABLE set after disabling"
        );
    }

    #[test]
    fn test_sigaltstack_too_small() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // size < MINSIGSTKSZ (2048) → ENOMEM.
        let ss = make_stack_t(0x80000, 0, MINSIGSTKSZ - 1);
        let r = lx.dispatch_syscall(LinuxSyscall::Sigaltstack {
            ss: ss.as_ptr() as u64,
            old_ss: 0,
        });
        assert_eq!(r, ENOMEM, "undersized stack should return ENOMEM");
    }

    #[test]
    fn test_sigaltstack_eperm_on_altstack() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Install a handler on SIGUSR1 (10) with SA_ONSTACK.
        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER | SA_SIGINFO | SA_ONSTACK;
        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, 0, restorer_addr);

        // Configure a valid alt stack in the arena so setup_signal_frame can write to it.
        let arena_base = lx.arena_base() as u64;
        // Place the alt stack near the top of the arena (0x80000 offset, size 0x10000).
        let alt_sp = arena_base + 0x80000;
        let alt_size: u64 = 0x10000;
        let ss = make_stack_t(alt_sp, 0, alt_size);
        let r = lx.dispatch_syscall(LinuxSyscall::Sigaltstack {
            ss: ss.as_ptr() as u64,
            old_ss: 0,
        });
        assert_eq!(r, 0, "initial sigaltstack setup should succeed");

        // Send SIGUSR1 to self so a pending signal is queued.
        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        assert_eq!(
            lx.pending_handler_signal(),
            Some(10),
            "signal 10 should be pending"
        );

        // Call setup_signal_frame — this sets on_alt_stack = true.
        let rsp = alt_sp + alt_size - 0x100;
        let regs = SavedRegisters {
            rsp,
            ..SavedRegisters::default()
        };
        let _setup = lx.setup_signal_frame(10, &regs);

        // Now trying to reconfigure sigaltstack should return EPERM.
        let ss2 = make_stack_t(alt_sp, 0, alt_size);
        let r = lx.dispatch_syscall(LinuxSyscall::Sigaltstack {
            ss: ss2.as_ptr() as u64,
            old_ss: 0,
        });
        assert_eq!(
            r, EPERM,
            "sigaltstack should return EPERM while on alt stack"
        );
    }

    #[test]
    fn test_sigaltstack_onstack() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Configure alt stack at sp=arena+0x70000, size=8192.
        let arena_base = lx.arena_base() as u64;
        let alt_sp = arena_base + 0x70000;
        let alt_size: u64 = 8192;
        let ss = make_stack_t(alt_sp, 0, alt_size);
        let r = lx.dispatch_syscall(LinuxSyscall::Sigaltstack {
            ss: ss.as_ptr() as u64,
            old_ss: 0,
        });
        assert_eq!(r, 0, "sigaltstack set should succeed");

        // Install SA_ONSTACK|SA_RESTORER|SA_SIGINFO handler for sig 10.
        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_ONSTACK | SA_RESTORER | SA_SIGINFO;
        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, 0, restorer_addr);

        // Kill to queue signal, deliver it.
        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        let sig = lx.pending_handler_signal();
        assert_eq!(sig, Some(10));

        // RSP on the alt stack itself (will be ignored — frame goes on alt stack).
        let rsp = alt_sp + alt_size / 2;
        let regs = SavedRegisters {
            rsp,
            ..SavedRegisters::default()
        };

        let setup = lx.setup_signal_frame(10, &regs);

        // handler_rsp must lie within the alt stack range [alt_sp, alt_sp + alt_size).
        assert!(
            setup.handler_rsp >= alt_sp,
            "handler_rsp {:#x} must be >= alt_sp {:#x}",
            setup.handler_rsp,
            alt_sp
        );
        assert!(
            setup.handler_rsp < alt_sp + alt_size,
            "handler_rsp {:#x} must be < alt_sp+size {:#x}",
            setup.handler_rsp,
            alt_sp + alt_size
        );
    }

    #[test]
    fn test_sigreturn_clears_on_alt_stack() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Configure alt stack at sp=arena+0x70000, size=8192.
        let arena_base = lx.arena_base() as u64;
        let alt_sp = arena_base + 0x70000;
        let alt_size: u64 = 8192;
        let ss = make_stack_t(alt_sp, 0, alt_size);
        lx.dispatch_syscall(LinuxSyscall::Sigaltstack {
            ss: ss.as_ptr() as u64,
            old_ss: 0,
        });

        // Install SA_ONSTACK handler.
        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_ONSTACK | SA_RESTORER | SA_SIGINFO;
        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, 0, restorer_addr);

        // Deliver signal and set up frame.
        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        lx.pending_handler_signal();

        let rsp = alt_sp + alt_size / 2;
        let regs = SavedRegisters {
            rsp,
            ..SavedRegisters::default()
        };
        let setup = lx.setup_signal_frame(10, &regs);

        // After setup_signal_frame, SS_ONSTACK should be reported in old_ss flags.
        let mut old = [0u8; 24];
        lx.dispatch_syscall(LinuxSyscall::Sigaltstack {
            ss: 0,
            old_ss: old.as_mut_ptr() as u64,
        });
        let flags_during = i32::from_ne_bytes(old[8..12].try_into().unwrap());
        assert_ne!(
            flags_during & SS_ONSTACK,
            0,
            "SS_ONSTACK must be set in old_ss flags while on alt stack"
        );

        // rt_sigreturn: restore state from the saved frame.
        let sigreturn_rsp = setup.handler_rsp + 8;
        lx.dispatch_syscall(LinuxSyscall::RtSigreturn { rsp: sigreturn_rsp });
        lx.pending_signal_return();

        // After sigreturn, SS_ONSTACK should be cleared.
        let mut old2 = [0u8; 24];
        lx.dispatch_syscall(LinuxSyscall::Sigaltstack {
            ss: 0,
            old_ss: old2.as_mut_ptr() as u64,
        });
        let flags_after = i32::from_ne_bytes(old2[8..12].try_into().unwrap());
        assert_eq!(
            flags_after & SS_ONSTACK,
            0,
            "SS_ONSTACK must be cleared after rt_sigreturn"
        );
    }

    #[test]
    fn test_restorer_as_return_addr() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0xDEAD_BEEF;
        let flags = SA_RESTORER | SA_SIGINFO;
        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, 0, restorer_addr);

        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        lx.pending_handler_signal();

        let rsp = (lx.arena_base() + 0x50000) as u64;
        let regs = SavedRegisters {
            rsp,
            ..SavedRegisters::default()
        };

        let setup = lx.setup_signal_frame(10, &regs);

        // The u64 at handler_rsp is the return address — must equal sa_restorer.
        let retaddr = unsafe { core::ptr::read_unaligned(setup.handler_rsp as *const u64) };
        assert_eq!(
            retaddr, restorer_addr,
            "return address at handler_rsp must equal sa_restorer"
        );
    }

    #[test]
    fn test_frame_rsp_alignment() {
        // For each initial RSP value, verify handler_rsp ≡ 8 (mod 16).
        let rsp_values: &[u64] = &[0x50000, 0x50008, 0x50010, 0x4FFF8, 0x4FFF0];

        for &init_rsp in rsp_values {
            // Fresh Linuxulator for each iteration to avoid blocked-signal state.
            let mock = MockBackend::new();
            let mut lx = Linuxulator::new(mock);

            let arena_base = lx.arena_base() as u64;
            let handler_addr: u64 = 0x400000;
            let restorer_addr: u64 = 0x401000;
            let flags = SA_RESTORER | SA_SIGINFO;
            install_handler_with_restorer(&mut lx, 10, handler_addr, flags, 0, restorer_addr);

            lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
            lx.pending_handler_signal();

            // Use arena_base + init_rsp so frame lands in writable memory.
            let rsp = arena_base + init_rsp;
            let regs = SavedRegisters {
                rsp,
                ..SavedRegisters::default()
            };

            let setup = lx.setup_signal_frame(10, &regs);
            assert_eq!(
                setup.handler_rsp % 16,
                8,
                "handler_rsp {:#x} must be ≡ 8 (mod 16) for init_rsp offset {:#x}",
                setup.handler_rsp,
                init_rsp
            );
        }
    }

    #[test]
    fn test_sa_siginfo_three_arg() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Install handler WITHOUT SA_SIGINFO — only SA_RESTORER.
        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER; // no SA_SIGINFO
        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, 0, restorer_addr);

        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        lx.pending_handler_signal();

        let rsp = (lx.arena_base() + 0x50000) as u64;
        let regs = SavedRegisters {
            rsp,
            ..SavedRegisters::default()
        };

        let setup = lx.setup_signal_frame(10, &regs);

        // Without SA_SIGINFO: rsi and rdx must be 0; rdi is the signal number.
        assert_eq!(setup.rdi, 10, "rdi must be the signal number");
        assert_eq!(setup.rsi, 0, "rsi must be 0 without SA_SIGINFO");
        assert_eq!(setup.rdx, 0, "rdx must be 0 without SA_SIGINFO");
    }

    #[test]
    fn test_fork_inherits_alt_stack() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Configure alt stack on parent.
        let arena_base = lx.arena_base() as u64;
        let alt_sp = arena_base + 0x70000;
        let alt_size: u64 = 8192;
        let ss = make_stack_t(alt_sp, 0, alt_size);
        let r = lx.dispatch_syscall(LinuxSyscall::Sigaltstack {
            ss: ss.as_ptr() as u64,
            old_ss: 0,
        });
        assert_eq!(r, 0, "parent sigaltstack set should succeed");

        // Fork.
        lx.dispatch_syscall(LinuxSyscall::Fork);

        // Get access to the child via pending_fork_child.
        let (_child_pid, child) = lx
            .pending_fork_child()
            .expect("child linuxulator must be pending after fork");

        // Read child's alt stack via sigaltstack(NULL, &old_ss).
        let mut old = [0u8; 24];
        let r = child.dispatch_syscall(LinuxSyscall::Sigaltstack {
            ss: 0,
            old_ss: old.as_mut_ptr() as u64,
        });
        assert_eq!(r, 0, "child sigaltstack get should succeed");

        let sp_out = u64::from_ne_bytes(old[0..8].try_into().unwrap());
        let size_out = u64::from_ne_bytes(old[16..24].try_into().unwrap());

        assert_eq!(sp_out, alt_sp, "child must inherit parent alt stack sp");
        assert_eq!(
            size_out, alt_size,
            "child must inherit parent alt stack size"
        );
    }

    #[test]
    fn test_socket_dgram_creates_fd() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // AF_INET (2), SOCK_DGRAM (2), protocol 0
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,
            sock_type: 2,
            protocol: 0,
        });
        assert!(
            fd >= 0,
            "socket(AF_INET, SOCK_DGRAM) should return valid fd, got {fd}"
        );
        assert!(lx.has_fd(fd as i32));
    }

    #[test]
    fn test_udp_readiness_stub() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,    // AF_INET
            sock_type: 2, // SOCK_DGRAM
            protocol: 0,
        }) as i32;
        assert!(fd >= 0);

        // With NoTcp, udp_create fails → no udp_handle → stub path.
        assert!(lx.is_fd_readable(fd));
        assert!(lx.is_fd_writable(fd));
    }

    #[test]
    fn test_parse_sockaddr_in() {
        let mock = MockBackend::new();
        let lx = Linuxulator::new(mock);

        // Build a valid sockaddr_in: AF_INET=2, port=8080, addr=10.0.0.1
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
        sa[2..4].copy_from_slice(&8080u16.to_be_bytes());
        sa[4..8].copy_from_slice(&[10, 0, 0, 1]);

        let result = lx.parse_sockaddr_in(sa.as_ptr() as u64, 16);
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(port, 8080);
        assert_eq!(
            ip,
            harmony_netstack::smoltcp::wire::Ipv4Address::new(10, 0, 0, 1)
        );
    }

    #[test]
    fn test_parse_sockaddr_in_null() {
        let mock = MockBackend::new();
        let lx = Linuxulator::new(mock);
        assert!(lx.parse_sockaddr_in(0, 16).is_none());
    }

    #[test]
    fn test_parse_sockaddr_in_too_short() {
        let mock = MockBackend::new();
        let lx = Linuxulator::new(mock);
        let sa = [0u8; 4];
        assert!(lx.parse_sockaddr_in(sa.as_ptr() as u64, 4).is_none());
    }

    // ── Blocking I/O tests ───────────────────────────────────────────────────

    use core::sync::atomic::{AtomicU64, Ordering};

    /// Poll function for blocking I/O tests. Each call advances time by
    /// 31 seconds, ensuring `block_until` times out on the second call.
    fn timeout_poll_fn() -> u64 {
        static TIME: AtomicU64 = AtomicU64::new(0);
        TIME.fetch_add(31_000, Ordering::Relaxed)
    }

    #[test]
    fn blocking_pipe_read_returns_data() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);
        let (rfd, wfd) = create_pipe(&mut lx);

        let data = b"hello";
        let w = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: wfd,
            buf: data.as_ptr() as u64,
            count: data.len() as u64,
        });
        assert_eq!(w, 5);

        let mut buf = [0u8; 16];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: rfd,
            buf: buf.as_mut_ptr() as u64,
            count: buf.len() as u64,
        });
        assert_eq!(r, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn blocking_pipe_read_empty_returns_eagain() {
        // When block_fn is None (no scheduler), block_until returns Interrupted.
        // The correct errno in that case is EAGAIN (not EINTR).
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);
        let (rfd, _wfd) = create_pipe(&mut lx);

        let mut buf = [0u8; 16];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: rfd,
            buf: buf.as_mut_ptr() as u64,
            count: buf.len() as u64,
        });
        assert_eq!(r, EAGAIN);
    }

    #[test]
    fn blocking_pipe_read_eof_returns_zero() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);
        let (rfd, wfd) = create_pipe(&mut lx);

        lx.dispatch_syscall(LinuxSyscall::Close { fd: wfd });

        let mut buf = [0u8; 16];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: rfd,
            buf: buf.as_mut_ptr() as u64,
            count: buf.len() as u64,
        });
        assert_eq!(r, 0);
    }

    #[test]
    fn nonblocking_pipe_read_empty_returns_eagain() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);
        let mut fds = [0i32; 2];
        let result = lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0o4000, // O_NONBLOCK
        });
        assert_eq!(result, 0);

        let mut buf = [0u8; 16];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: fds[0],
            buf: buf.as_mut_ptr() as u64,
            count: buf.len() as u64,
        });
        assert_eq!(r, EAGAIN);
    }

    #[test]
    fn blocking_pipe_write_broken_pipe_returns_epipe() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);
        let (rfd, wfd) = create_pipe(&mut lx);

        // Close read end.
        lx.dispatch_syscall(LinuxSyscall::Close { fd: rfd });

        // Blocking write to pipe with no reader → EPIPE.
        let data = b"hello";
        let r = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: wfd,
            buf: data.as_ptr() as u64,
            count: data.len() as u64,
        });
        assert_eq!(r, EPIPE);
    }

    #[test]
    fn blocking_pipe_write_full_returns_eagain_without_scheduler() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);
        // Note: no block_fn set — no scheduler available.
        let (rfd, wfd) = create_pipe(&mut lx);

        // Fill the pipe buffer (65536 bytes).
        let big = [0u8; 65536];
        let w = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: wfd,
            buf: big.as_ptr() as u64,
            count: big.len() as u64,
        });
        assert_eq!(w, 65536);

        // Blocking write to full pipe with no scheduler → EAGAIN (no one to wake us).
        let data = b"overflow";
        let r = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: wfd,
            buf: data.as_ptr() as u64,
            count: data.len() as u64,
        });
        assert_eq!(r, EAGAIN);

        // Keep rfd alive so pipe isn't broken.
        let _ = rfd;
    }

    #[test]
    fn blocking_accept4_stub_returns_fd() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);

        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 1,    // AF_UNIX
            sock_type: 1, // SOCK_STREAM (blocking)
            protocol: 0,
        });
        assert!(fd >= 0);
        lx.dispatch_syscall(LinuxSyscall::Listen {
            fd: fd as i32,
            backlog: 128,
        });

        let c1 = lx.dispatch_syscall(LinuxSyscall::Accept4 {
            fd: fd as i32,
            addr: 0,
            addrlen: 0,
            flags: 0,
        });
        assert!(c1 >= 0);

        // Second blocking accept on stub — stub sockets are always "ready"
        // per is_fd_readable, so block_until returns Ready immediately.
        // Blocking mode prevents the accepted_once EAGAIN guard.
        let c2 = lx.dispatch_syscall(LinuxSyscall::Accept4 {
            fd: fd as i32,
            addr: 0,
            addrlen: 0,
            flags: 0,
        });
        assert!(c2 >= 0);
        assert_ne!(c2, c1);
    }

    #[test]
    fn nonblocking_accept4_returns_eagain() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);

        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 1,           // AF_UNIX
            sock_type: 1 | 2048, // SOCK_STREAM | SOCK_NONBLOCK
            protocol: 0,
        });
        assert!(fd >= 0);
        lx.dispatch_syscall(LinuxSyscall::Listen {
            fd: fd as i32,
            backlog: 128,
        });

        let c1 = lx.dispatch_syscall(LinuxSyscall::Accept4 {
            fd: fd as i32,
            addr: 0,
            addrlen: 0,
            flags: 0,
        });
        assert!(c1 >= 0);

        // Second nonblocking accept → EAGAIN (accepted_once guard).
        let c2 = lx.dispatch_syscall(LinuxSyscall::Accept4 {
            fd: fd as i32,
            addr: 0,
            addrlen: 0,
            flags: 0,
        });
        assert_eq!(c2, EAGAIN);
    }

    #[test]
    fn nonblocking_pipe_write_full_returns_eagain() {
        let mut lx = Linuxulator::new(MockBackend::new());
        let mut fds = [0i32; 2];
        let result = lx.dispatch_syscall(LinuxSyscall::Pipe2 {
            fds: fds.as_mut_ptr() as u64,
            flags: 0o4000, // O_NONBLOCK
        });
        assert_eq!(result, 0);

        // Fill the pipe buffer.
        let big = [0u8; 65536];
        let w = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: fds[1],
            buf: big.as_ptr() as u64,
            count: big.len() as u64,
        });
        assert_eq!(w, 65536);

        // Nonblocking write to full pipe → EAGAIN.
        let data = b"overflow";
        let r = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: fds[1],
            buf: data.as_ptr() as u64,
            count: data.len() as u64,
        });
        assert_eq!(r, EAGAIN);
    }

    #[test]
    fn blocking_udp_stub_recvfrom_returns_eof() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);

        // Create blocking UDP socket (NoTcp → udp_handle is None).
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,    // AF_INET
            sock_type: 2, // SOCK_DGRAM (blocking)
            protocol: 0,
        });
        assert!(fd >= 0);

        // With NoTcp, recvfrom returns 0 (stub EOF).
        let mut buf = [0u8; 16];
        let r = lx.dispatch_syscall(LinuxSyscall::Recvfrom {
            fd: fd as i32,
            buf: buf.as_mut_ptr() as u64,
            len: buf.len() as u64,
            flags: 0,
            src_addr: 0,
            addrlen: 0,
        });
        assert_eq!(r, 0);
    }

    #[test]
    fn blocking_tcp_connect_stub_returns_zero() {
        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_poll_fn(timeout_poll_fn);

        // Create a blocking TCP socket. With NoTcp, tcp_handle is None,
        // so connect falls to the stub path (returns 0 for non-AF_UNIX).
        let fd = lx.dispatch_syscall(LinuxSyscall::Socket {
            domain: 2,    // AF_INET
            sock_type: 1, // SOCK_STREAM (blocking)
            protocol: 0,
        });
        assert!(fd >= 0);

        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
        sa[2..4].copy_from_slice(&80u16.to_be_bytes()); // port 80
        sa[4..8].copy_from_slice(&[10, 0, 0, 1]); // 10.0.0.1
        let r = lx.dispatch_syscall(LinuxSyscall::Connect {
            fd: fd as i32,
            addr: sa.as_ptr() as u64,
            addrlen: 16,
        });
        // NoTcp → tcp_handle is None → stub returns 0.
        assert_eq!(r, 0);
    }

    #[test]
    fn block_until_calls_block_fn() {
        use core::sync::atomic::{AtomicBool, Ordering};

        let mut lx = Linuxulator::new(MockBackend::new());
        static BLOCK_CALLED: AtomicBool = AtomicBool::new(false);

        lx.set_block_fn(|_op, _fd| {
            BLOCK_CALLED.store(true, Ordering::SeqCst);
        });

        BLOCK_CALLED.store(false, Ordering::SeqCst);
        let result = lx.block_until(BLOCK_OP_READABLE, 5);
        assert!(BLOCK_CALLED.load(Ordering::SeqCst));
        assert_eq!(result, BlockResult::Ready);
    }

    #[test]
    fn block_until_returns_interrupted_without_block_fn() {
        let mut lx = Linuxulator::new(MockBackend::new());
        // No block_fn set — should return Interrupted
        let result = lx.block_until(BLOCK_OP_READABLE, 5);
        assert_eq!(result, BlockResult::Interrupted);
    }

    #[test]
    fn is_wait_ready_op3_always_true() {
        let lx = Linuxulator::new(MockBackend::new());
        assert!(lx.is_wait_ready(BLOCK_OP_POLL, -1));
    }

    #[test]
    fn is_wait_ready_unknown_op_returns_false() {
        let lx = Linuxulator::new(MockBackend::new());
        assert!(!lx.is_wait_ready(42, -1));
    }

    #[test]
    fn poll_network_no_panic_without_poll_fn() {
        let mut lx = Linuxulator::new(MockBackend::new());
        // Should not panic when poll_fn is None
        lx.poll_network();
    }

    // ── find_pipe_read_fd / find_pipe_write_fd tests ─────────────────────────

    #[test]
    fn find_pipe_write_fd_returns_correct_fd() {
        let mut lx = Linuxulator::new(MockBackend::new());
        let (rfd, wfd) = create_pipe(&mut lx);
        // The write fd must be findable by its pipe_id.
        let pipe_id = match lx.fd_table.get(&wfd) {
            Some(e) => match e.kind {
                FdKind::PipeWrite { pipe_id } => pipe_id,
                _ => panic!("expected PipeWrite"),
            },
            None => panic!("wfd not found"),
        };
        let found = lx.find_pipe_write_fd(pipe_id);
        assert_eq!(found, Some(wfd));
        // The read fd is not a PipeWrite — should not be returned.
        let _ = rfd; // used for pipe creation only
    }

    #[test]
    fn find_pipe_read_fd_returns_correct_fd() {
        let mut lx = Linuxulator::new(MockBackend::new());
        let (rfd, wfd) = create_pipe(&mut lx);
        // The read fd must be findable by its pipe_id.
        let pipe_id = match lx.fd_table.get(&rfd) {
            Some(e) => match e.kind {
                FdKind::PipeRead { pipe_id } => pipe_id,
                _ => panic!("expected PipeRead"),
            },
            None => panic!("rfd not found"),
        };
        let found = lx.find_pipe_read_fd(pipe_id);
        assert_eq!(found, Some(rfd));
        // The write fd is not a PipeRead — should not be returned.
        let _ = wfd; // used for pipe creation only
    }

    #[test]
    fn find_pipe_write_fd_returns_none_when_not_found() {
        let lx = Linuxulator::new(MockBackend::new());
        // No pipes in this linuxulator — should return None.
        assert_eq!(lx.find_pipe_write_fd(99), None);
    }

    #[test]
    fn find_pipe_read_fd_returns_none_when_not_found() {
        let lx = Linuxulator::new(MockBackend::new());
        // No pipes in this linuxulator — should return None.
        assert_eq!(lx.find_pipe_read_fd(99), None);
    }

    #[test]
    fn pipe_write_calls_wake_fn_for_reader() {
        use core::sync::atomic::{AtomicI32, Ordering};
        static WOKEN_FD: AtomicI32 = AtomicI32::new(-1);

        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_wake_fn(|fd, _op| {
            WOKEN_FD.store(fd, Ordering::SeqCst);
        });

        let (rfd, wfd) = create_pipe(&mut lx);
        let data = b"ping";
        let r = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: wfd,
            buf: data.as_ptr() as u64,
            count: data.len() as u64,
        });
        assert_eq!(r, 4);
        // wake_fn should have been called with the read end fd.
        assert_eq!(WOKEN_FD.load(Ordering::SeqCst), rfd);
    }

    #[test]
    fn pipe_read_calls_wake_fn_for_writer() {
        use core::sync::atomic::{AtomicI32, Ordering};
        static WOKEN_FD: AtomicI32 = AtomicI32::new(-1);

        let mut lx = Linuxulator::new(MockBackend::new());
        lx.set_wake_fn(|fd, _op| {
            WOKEN_FD.store(fd, Ordering::SeqCst);
        });

        let (rfd, wfd) = create_pipe(&mut lx);
        let data = b"pong";
        // Write data first (wake_fn will fire but we reset after).
        let _ = lx.dispatch_syscall(LinuxSyscall::Write {
            fd: wfd,
            buf: data.as_ptr() as u64,
            count: data.len() as u64,
        });
        WOKEN_FD.store(-1, Ordering::SeqCst);

        // Now read — should wake the writer.
        let mut buf = [0u8; 4];
        let r = lx.dispatch_syscall(LinuxSyscall::Read {
            fd: rfd,
            buf: buf.as_mut_ptr() as u64,
            count: buf.len() as u64,
        });
        assert_eq!(r, 4);
        // wake_fn should have been called with the write end fd.
        assert_eq!(WOKEN_FD.load(Ordering::SeqCst), wfd);
    }
}
