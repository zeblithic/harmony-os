// SPDX-License-Identifier: GPL-2.0-or-later
//! Graduated Linux syscall test binary for Linuxulator validation.
//!
//! Cross-compiled to `aarch64-unknown-linux-musl` (static, no_std, no_main).
//! Each step exercises a different syscall and prints a result line prefixed
//! with `[LINUXULATOR]` so the QEMU boot test can grep for pass/fail.

#![no_std]
#![no_main]

// ---------------------------------------------------------------------------
// aarch64 Linux syscall numbers
// ---------------------------------------------------------------------------
const SYS_WRITE: u64 = 64;
const SYS_EXIT_GROUP: u64 = 94;
const SYS_BRK: u64 = 214;
const SYS_MUNMAP: u64 = 215;
const SYS_MMAP: u64 = 222;
const SYS_NEWFSTATAT: u64 = 79;
const SYS_CLOCK_GETTIME: u64 = 113;
const SYS_UNAME: u64 = 160;
const SYS_GETPID: u64 = 172;
const SYS_GETRANDOM: u64 = 278;

// mmap constants
const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

// File descriptors
const STDOUT: u64 = 1;
const STDERR: u64 = 2;

// ---------------------------------------------------------------------------
// Raw syscall wrappers (aarch64: svc #0, nr in x8, args in x0-x5, ret in x0)
// ---------------------------------------------------------------------------

#[inline(always)]
unsafe fn syscall0(nr: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "svc #0",
        in("x8") nr,
        lateout("x0") ret,
        options(nostack),
    );
    ret
}

#[inline(always)]
unsafe fn syscall1(nr: u64, a0: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "svc #0",
        in("x8") nr,
        inlateout("x0") a0 => ret,
        options(nostack),
    );
    ret
}

#[inline(always)]
unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "svc #0",
        in("x8") nr,
        inlateout("x0") a0 => ret,
        in("x1") a1,
        options(nostack),
    );
    ret
}

#[inline(always)]
unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "svc #0",
        in("x8") nr,
        inlateout("x0") a0 => ret,
        in("x1") a1,
        in("x2") a2,
        options(nostack),
    );
    ret
}

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

#[inline(always)]
unsafe fn syscall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "svc #0",
        in("x8") nr,
        inlateout("x0") a0 => ret,
        in("x1") a1,
        in("x2") a2,
        in("x3") a3,
        in("x4") a4,
        in("x5") a5,
        options(nostack),
    );
    ret
}

// ---------------------------------------------------------------------------
// Helper: write bytes to a file descriptor
// ---------------------------------------------------------------------------

unsafe fn write_fd(fd: u64, buf: &[u8]) -> i64 {
    syscall3(SYS_WRITE, fd, buf.as_ptr() as u64, buf.len() as u64)
}

unsafe fn write_stdout(msg: &[u8]) {
    write_fd(STDOUT, msg);
}

unsafe fn exit_group(code: u64) -> ! {
    syscall1(SYS_EXIT_GROUP, code);
    // Unreachable — kernel terminates the process. The loop satisfies `-> !`.
    #[allow(clippy::empty_loop)]
    loop {}
}

// ---------------------------------------------------------------------------
// Test steps
// ---------------------------------------------------------------------------

/// Step 1: write(1, "Hello from Harmony Linuxulator\n")
unsafe fn step1_write() -> bool {
    let msg = b"Hello from Harmony Linuxulator\n";
    let ret = write_fd(STDOUT, msg);
    ret == msg.len() as i64
}

/// Step 2: mmap anonymous memory, write+read, munmap
unsafe fn step2_mmap() -> bool {
    let size: u64 = 4096;
    let addr = syscall6(
        SYS_MMAP,
        0,                              // addr = NULL
        size,                           // length
        PROT_READ | PROT_WRITE,         // prot
        MAP_PRIVATE | MAP_ANONYMOUS,    // flags
        (-1i64) as u64,                 // fd = -1 (anonymous mapping)
        0,                              // offset
    );

    // mmap returns negative errno on failure
    if addr < 0 {
        return false;
    }

    let ptr = addr as *mut u8;

    // Write a known pattern
    *ptr = 0xAA;
    *ptr.add(1) = 0x55;
    *ptr.add(4095) = 0xBB;

    // Read back and verify
    let ok = *ptr == 0xAA && *ptr.add(1) == 0x55 && *ptr.add(4095) == 0xBB;

    // munmap
    let ret = syscall2(SYS_MUNMAP, addr as u64, size);
    ok && ret == 0
}

/// Step 3: brk(0) to get current break, brk(+4096) to expand
unsafe fn step3_brk() -> bool {
    let current = syscall1(SYS_BRK, 0);
    if current < 0 {
        return false;
    }

    let new_brk = syscall1(SYS_BRK, (current + 4096) as u64);
    // brk returns the new program break; on failure it returns the old one
    new_brk == current + 4096
}

/// Step 4: getrandom(buf, 16, 0) — get 16 random bytes
unsafe fn step4_getrandom() -> bool {
    let mut buf = [0u8; 16];
    let ret = syscall3(
        SYS_GETRANDOM,
        buf.as_mut_ptr() as u64,
        16,
        0, // flags = 0
    );

    if ret != 16 {
        return false;
    }

    // Verify we got something non-trivial (not all zeros)
    let mut all_zero = true;
    let mut i = 0;
    while i < 16 {
        if buf[i] != 0 {
            all_zero = false;
        }
        i += 1;
    }
    !all_zero
}

/// Step 5: newfstatat(stdout, "", &statbuf, AT_EMPTY_PATH)
/// Verifies stat-by-fd works through the SVC handler.
unsafe fn step5_newfstatat() -> bool {
    // Use MaybeUninit to avoid a memset/memcpy call (no libc in no_std).
    // The kernel fills the buffer on success; we read via raw pointer.
    let mut statbuf: core::mem::MaybeUninit<[u8; 128]> = core::mem::MaybeUninit::uninit();
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
    // Read bytes via pointer to avoid memcpy from assume_init().
    let p = statbuf.as_ptr() as *const u8;
    let mode = u32::from_le_bytes([
        *p.add(16),
        *p.add(17),
        *p.add(18),
        *p.add(19),
    ]);
    mode == 0o020666
}

/// Step 6: getpid — verify we get a positive pid (Linuxulator returns 1)
unsafe fn step6_getpid() -> bool {
    let pid = syscall0(SYS_GETPID);
    pid > 0
}

/// Step 7: clock_gettime(CLOCK_MONOTONIC) — verify it returns a non-zero timestamp
unsafe fn step7_clock_gettime() -> bool {
    // timespec: tv_sec (i64) + tv_nsec (i64) = 16 bytes
    let mut ts: core::mem::MaybeUninit<[u8; 16]> = core::mem::MaybeUninit::uninit();
    let clock_monotonic: u64 = 1;
    let ret = syscall2(SYS_CLOCK_GETTIME, clock_monotonic, ts.as_mut_ptr() as u64);
    if ret != 0 {
        return false;
    }
    let p = ts.as_ptr() as *const u8;
    let tv_sec = i64::from_le_bytes([
        *p,
        *p.add(1),
        *p.add(2),
        *p.add(3),
        *p.add(4),
        *p.add(5),
        *p.add(6),
        *p.add(7),
    ]);
    let tv_nsec = i64::from_le_bytes([
        *p.add(8),
        *p.add(9),
        *p.add(10),
        *p.add(11),
        *p.add(12),
        *p.add(13),
        *p.add(14),
        *p.add(15),
    ]);
    tv_sec != 0 || tv_nsec != 0
}

/// Step 8: uname — verify sysname starts with "Linux"
unsafe fn step8_uname() -> bool {
    // struct utsname is 390 bytes (5 × 65-byte fields + 1 × 65-byte domainname)
    let mut buf: core::mem::MaybeUninit<[u8; 390]> = core::mem::MaybeUninit::uninit();
    let ret = syscall1(SYS_UNAME, buf.as_mut_ptr() as u64);
    if ret != 0 {
        return false;
    }
    // sysname is the first field — check it starts with "Linux"
    let p = buf.as_ptr() as *const u8;
    *p == b'L' && *p.add(1) == b'i' && *p.add(2) == b'n' && *p.add(3) == b'u' && *p.add(4) == b'x'
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        let mut all_ok = true;

        // Step 1: write
        if step1_write() {
            write_stdout(b"[LINUXULATOR] Step 1 (write): OK\n");
        } else {
            write_stdout(b"[LINUXULATOR] Step 1 (write): FAIL\n");
            all_ok = false;
        }

        // Step 2: mmap + munmap
        if step2_mmap() {
            write_stdout(b"[LINUXULATOR] Step 2 (mmap): OK\n");
        } else {
            write_stdout(b"[LINUXULATOR] Step 2 (mmap): FAIL\n");
            all_ok = false;
        }

        // Step 3: brk
        if step3_brk() {
            write_stdout(b"[LINUXULATOR] Step 3 (brk): OK\n");
        } else {
            write_stdout(b"[LINUXULATOR] Step 3 (brk): FAIL\n");
            all_ok = false;
        }

        // Step 4: getrandom
        if step4_getrandom() {
            write_stdout(b"[LINUXULATOR] Step 4 (getrandom): OK\n");
        } else {
            write_stdout(b"[LINUXULATOR] Step 4 (getrandom): FAIL\n");
            all_ok = false;
        }

        // Step 5: newfstatat
        if step5_newfstatat() {
            write_stdout(b"[LINUXULATOR] Step 5 (newfstatat): OK\n");
        } else {
            write_stdout(b"[LINUXULATOR] Step 5 (newfstatat): FAIL\n");
            all_ok = false;
        }

        // Step 6: getpid
        if step6_getpid() {
            write_stdout(b"[LINUXULATOR] Step 6 (getpid): OK\n");
        } else {
            write_stdout(b"[LINUXULATOR] Step 6 (getpid): FAIL\n");
            all_ok = false;
        }

        // Step 7: clock_gettime
        if step7_clock_gettime() {
            write_stdout(b"[LINUXULATOR] Step 7 (clock_gettime): OK\n");
        } else {
            write_stdout(b"[LINUXULATOR] Step 7 (clock_gettime): FAIL\n");
            all_ok = false;
        }

        // Step 8: uname
        if step8_uname() {
            write_stdout(b"[LINUXULATOR] Step 8 (uname): OK\n");
        } else {
            write_stdout(b"[LINUXULATOR] Step 8 (uname): FAIL\n");
            all_ok = false;
        }

        if all_ok {
            write_stdout(b"[LINUXULATOR] All tests passed\n");
            exit_group(0);
        } else {
            write_stdout(b"[LINUXULATOR] Some tests FAILED\n");
            exit_group(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Panic handler — write to stderr and exit
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        write_fd(STDERR, b"[LINUXULATOR] PANIC\n");
        exit_group(1);
    }
}
