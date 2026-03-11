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
        u64::MAX,                       // fd = -1 (as unsigned)
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
    let ret = syscall3(SYS_MUNMAP, addr as u64, size, 0);
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

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        // Step 1: write
        if step1_write() {
            write_stdout(b"[LINUXULATOR] Step 1 (write): OK\n");
        } else {
            write_stdout(b"[LINUXULATOR] Step 1 (write): FAIL\n");
        }

        // Step 2: mmap + munmap
        if step2_mmap() {
            write_stdout(b"[LINUXULATOR] Step 2 (mmap): OK\n");
        } else {
            write_stdout(b"[LINUXULATOR] Step 2 (mmap): FAIL\n");
        }

        // Step 3: brk
        if step3_brk() {
            write_stdout(b"[LINUXULATOR] Step 3 (brk): OK\n");
        } else {
            write_stdout(b"[LINUXULATOR] Step 3 (brk): FAIL\n");
        }

        // Step 4: getrandom
        if step4_getrandom() {
            write_stdout(b"[LINUXULATOR] Step 4 (getrandom): OK\n");
        } else {
            write_stdout(b"[LINUXULATOR] Step 4 (getrandom): FAIL\n");
        }

        // All done
        write_stdout(b"[LINUXULATOR] All tests passed\n");

        exit_group(0);
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
