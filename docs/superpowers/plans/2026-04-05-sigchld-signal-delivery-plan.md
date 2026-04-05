# Signal Delivery Infrastructure (SIGCHLD) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port signal frame infrastructure from x86_64 to aarch64, wire signal delivery into the boot code dispatch loop, and verify with SIGCHLD as the first real consumer.

**Architecture:** Three layers — linuxulator signal structs/frame/sigreturn behind `#[cfg(target_arch)]` (Tasks 1–4), then boot code wiring in dispatch()+svc_handler (Task 5). SIGCHLD siginfo populated via new `SigInfo` struct carried alongside `pending_handler_signal`. Existing x86_64 code preserved intact.

**Tech Stack:** Rust, `no_std`, `#[cfg(target_arch)]` conditional compilation, aarch64 inline asm for SP_EL0 access.

---

### Task 1: aarch64 Signal Structs + read_sigaction Fix

**Context:** The linuxulator has `SavedRegisters`, `SignalHandlerSetup`, and `SignalReturn` structs with x86_64 register names. These need aarch64 counterparts behind `cfg(target_arch)`. Additionally, `read_sigaction`/`write_sigaction` skip `sa_restorer` on non-x86_64, but aarch64 Linux's `struct sigaction` includes `sa_restorer` at the same offset as x86_64. This must be fixed or signal handlers will have restorer=0.

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs:2298-2343` (SavedRegisters, SignalHandlerSetup, SignalReturn)
- Modify: `crates/harmony-os/src/linuxulator.rs:7612-7675` (read_sigaction, write_sigaction)
- Modify: `crates/harmony-os/src/linuxulator.rs:17372-17393` (install_handler_with_restorer test helper)
- Test: `crates/harmony-os/src/linuxulator.rs` (existing tests, cfg-gate section header)

- [ ] **Step 1: cfg-gate existing x86_64 structs**

Add `#[cfg(target_arch = "x86_64")]` to the existing `SavedRegisters`, `SignalHandlerSetup`, and update `SignalReturn` to be cfg-gated:

```rust
/// Register state the caller provides for signal frame construction.
/// Matches the x86_64 GPR set needed for Linux sigcontext.
#[cfg(target_arch = "x86_64")]
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
#[cfg(target_arch = "x86_64")]
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
```

`SignalReturn` wraps `SavedRegisters` which is already cfg-gated, so it compiles on both architectures without its own cfg gate.

- [ ] **Step 2: Add aarch64 structs**

Add immediately after the x86_64 versions:

```rust
/// Register state for aarch64 signal frame construction.
/// Matches the aarch64 Linux sigcontext layout (regs[31], sp, pc, pstate)
/// plus FPSIMD state (fpcr, fpsr, q[0-31]).
#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SavedRegisters {
    /// General-purpose registers x0-x30.
    pub x: [u64; 31],
    /// User stack pointer (SP_EL0).
    pub sp: u64,
    /// Program counter (ELR_EL1 at exception time).
    pub pc: u64,
    /// Processor state (SPSR_EL1 at exception time).
    pub pstate: u64,
    /// Floating-point control register.
    pub fpcr: u64,
    /// Floating-point status register.
    pub fpsr: u64,
    /// SIMD/FP registers Q0-Q31 (128 bits each).
    pub q: [u128; 32],
}

/// Returned by `setup_signal_frame` — tells the caller where to jump
/// and what register values to set for signal handler invocation.
#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone, Copy)]
pub struct SignalHandlerSetup {
    /// Handler function address (set ELR to this).
    pub handler_pc: u64,
    /// Signal frame base on user stack (set SP_EL0 to this).
    pub handler_sp: u64,
    /// First argument: signal number (set x0).
    pub x0: u64,
    /// Second argument: pointer to siginfo_t (set x1). 0 if !SA_SIGINFO.
    pub x1: u64,
    /// Third argument: pointer to ucontext_t (set x2). 0 if !SA_SIGINFO.
    pub x2: u64,
    /// Link register: sa_restorer trampoline (set x30).
    pub x30: u64,
}
```

- [ ] **Step 3: Fix read_sigaction for aarch64**

In `read_sigaction` (line ~7613), change the cfg guards so aarch64 reads `sa_restorer` from bytes 16..24 (same offset as x86_64):

```rust
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

    // sa_restorer at offset 16 on x86_64 and aarch64 (both define SA_RESTORER).
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let restorer = u64::from_ne_bytes(
        unsafe { core::slice::from_raw_parts((addr + 16) as *const u8, 8) }
            .try_into()
            .unwrap(),
    );
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let restorer = 0u64;

    // sa_mask follows sa_restorer on architectures that have it.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let mask_offset = 24;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
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
```

- [ ] **Step 4: Fix write_sigaction for aarch64**

Same pattern — write restorer on aarch64 too (line ~7655):

```rust
fn write_sigaction(ptr: u64, action: &SignalAction) {
    let addr = ptr as usize;
    unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, 8) }
        .copy_from_slice(&action.handler.to_ne_bytes());
    unsafe { core::slice::from_raw_parts_mut((addr + 8) as *mut u8, 8) }
        .copy_from_slice(&action.flags.to_ne_bytes());

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        unsafe { core::slice::from_raw_parts_mut((addr + 16) as *mut u8, 8) }
            .copy_from_slice(&action.restorer.to_ne_bytes());
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let mask_offset = 24;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let mask_offset = 16;

    unsafe { core::slice::from_raw_parts_mut((addr + mask_offset) as *mut u8, 8) }
        .copy_from_slice(&action.mask.to_ne_bytes());
}
```

- [ ] **Step 5: Fix install_handler_with_restorer test helper**

Update the test helper (line ~17374) to write restorer on aarch64 too:

```rust
fn install_handler_with_restorer(
    lx: &mut Linuxulator<MockBackend>,
    signum: i32,
    handler: u64,
    flags: u64,
    mask: u64,
    restorer: u64,
) {
    let mut act = make_sigaction(handler, flags, mask);
    // sa_restorer at bytes 16..24 on x86_64 and aarch64.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    act[16..24].copy_from_slice(&restorer.to_ne_bytes());
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let _ = restorer;
    lx.dispatch_syscall(LinuxSyscall::RtSigaction {
        signum,
        act: act.as_ptr() as u64,
        oldact: 0,
        sigsetsize: 8,
    });
}
```

- [ ] **Step 6: Update SignalAction restorer doc comment**

Change the doc comment on `SignalAction.restorer` (line ~2351) from x86_64-only to both:

```rust
    /// sa_restorer (x86_64 and aarch64; 0 on other arches). Used for
    /// signal stack frame construction — points to the sigreturn trampoline.
    restorer: u64,
```

- [ ] **Step 7: Run tests**

Run: `cargo test -p harmony-os -- signal`
Expected: All existing signal tests pass. On aarch64 hosts, `SavedRegisters` now uses the aarch64 definition, but the signal frame tests are cfg-gated to x86_64 only (they reference x86_64 field names), so they don't compile on aarch64 yet. That's expected — aarch64 frame tests come in Task 3.

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "refactor: cfg-gate signal structs for x86_64/aarch64, fix read_sigaction restorer"
```

---

### Task 2: SigInfo Struct + Pending Siginfo Wiring

**Context:** When SIGCHLD is delivered, the siginfo_t needs si_code (CLD_EXITED/CLD_KILLED), si_pid, and si_status. Currently only si_signo is written. We need a `SigInfo` struct carried alongside `pending_handler_signal`, populated by `recover_child_state()` for SIGCHLD and by `queue_signal()` for kill/tgkill.

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs:60-101` (add SigInfo constants)
- Modify: `crates/harmony-os/src/linuxulator.rs:2470-2520` (new field)
- Modify: `crates/harmony-os/src/linuxulator.rs:2580-2620` (init)
- Modify: `crates/harmony-os/src/linuxulator.rs:2985-3018` (recover_child_state)
- Modify: `crates/harmony-os/src/linuxulator.rs:3062-3065` (pending_handler_signal)
- Modify: `crates/harmony-os/src/linuxulator.rs:4345-4406` (queue_signal, deliver_pending_signals)
- Modify: `crates/harmony-os/src/linuxulator.rs:6573-6614` (sys_kill, sys_tgkill)
- Test: `crates/harmony-os/src/linuxulator.rs` (new tests)

- [ ] **Step 1: Add SigInfo struct and constants**

Add after the BLOCK_OP constants (around line 101):

```rust
// siginfo si_code values for SIGCHLD
const CLD_EXITED: i32 = 1;
const CLD_KILLED: i32 = 2;
/// si_code for signals sent by kill()/tgkill().
const SI_USER: i32 = 0;

/// Signal-specific information passed to setup_signal_frame for siginfo_t population.
/// Architecture-neutral — both x86_64 and aarch64 use the same si_code/si_pid/si_status fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigInfo {
    pub si_code: i32,
    pub si_pid: i32,
    pub si_status: i32,
}
```

- [ ] **Step 2: Add pending_siginfo field to Linuxulator**

After `pending_handler_signal` (line ~2484):

```rust
    /// Signal with custom handler pending for caller invocation.
    pending_handler_signal: Option<u32>,
    /// Signal-specific info for the pending handler signal (SIGCHLD: child exit info).
    pending_siginfo: Option<SigInfo>,
```

Initialize in `new()` (after `pending_handler_signal: None`):

```rust
            pending_handler_signal: None,
            pending_siginfo: None,
```

- [ ] **Step 3: Add pending_siginfo consumer method and update pending_handler_signal**

After `pending_handler_signal()` (line ~3063):

```rust
    /// Consume the pending handler signal.
    pub fn pending_handler_signal(&mut self) -> Option<u32> {
        self.pending_handler_signal.take()
    }

    /// Consume the pending signal info (set alongside pending_handler_signal).
    pub fn pending_siginfo(&mut self) -> Option<SigInfo> {
        self.pending_siginfo.take()
    }
```

- [ ] **Step 4: Update recover_child_state to populate siginfo**

In `recover_child_state()` (line ~2999), after extracting child exit info, store the siginfo before queuing SIGCHLD:

```rust
    fn recover_child_state(&mut self) {
        let should_recover = self
            .children
            .last()
            .is_some_and(|c| c.linuxulator.exit_code.is_some());
        if !should_recover {
            return;
        }
        let child = self.children.pop().unwrap();
        let exit_code = child.linuxulator.exit_code.unwrap_or(0);
        let killed_by = child.linuxulator.killed_by_signal;
        self.exited_children.push((child.pid, exit_code, killed_by));

        let mut c = child.linuxulator;
        core::mem::swap(&mut self.pipes, &mut c.pipes);
        core::mem::swap(&mut self.eventfds, &mut c.eventfds);
        self.next_pipe_id = self.next_pipe_id.max(c.next_pipe_id);
        self.next_eventfd_id = self.next_eventfd_id.max(c.next_eventfd_id);
        self.next_child_pid = self.next_child_pid.max(c.next_child_pid);
        // Auto-deliver SIGCHLD to parent with child exit info.
        self.pending_signals |= 1u64 << (SIGCHLD_NUM - 1);
        self.pending_siginfo = Some(SigInfo {
            si_code: if killed_by.is_some() { CLD_KILLED } else { CLD_EXITED },
            si_pid: child.pid,
            si_status: if let Some(sig) = killed_by { sig as i32 } else { exit_code },
        });
    }
```

Note: `pending_siginfo` is set unconditionally when SIGCHLD is queued. If the handler is SIG_DFL (Ignore), `deliver_pending_signals` will clear the pending signal without consuming siginfo — that's fine, `pending_siginfo` will be overwritten or dropped.

- [ ] **Step 5: Update deliver_pending_signals to carry siginfo**

In `deliver_pending_signals()` (line ~4398), when setting `pending_handler_signal`, also copy `pending_siginfo`:

```rust
            _ => {
                debug_assert!(
                    self.pending_handler_signal.is_none(),
                    "pending_handler_signal overwritten: caller must consume after each dispatch_syscall"
                );
                self.pending_handler_signal = Some(signum);
                // pending_siginfo is already set by whoever queued this signal
                // (recover_child_state for SIGCHLD, queue_signal_with_info for
                // kill/tgkill). If no siginfo was set, it stays None — setup_signal_frame
                // will only write si_signo.
            }
```

Actually, there's a subtlety: `pending_siginfo` is set when the signal is queued (e.g., in `recover_child_state`), but it might be consumed or overwritten before `deliver_pending_signals` runs if multiple signals are pending. Since we only deliver one signal per syscall boundary, and `pending_siginfo` corresponds to the most recently queued signal, this is correct for the common case (SIGCHLD from child exit). For the rare case of multiple signals pending, the siginfo may not match — this is acceptable for minimum viable (Linux has a proper sigqueue for this).

- [ ] **Step 6: Update sys_kill and sys_tgkill to set siginfo**

In `sys_kill` (line ~6594), before `self.queue_signal`:

```rust
        self.pending_siginfo = Some(SigInfo {
            si_code: SI_USER,
            si_pid: self.pid,
            si_status: 0,
        });
        self.queue_signal(sig as u32);
```

In `sys_tgkill` (line ~6612), same pattern:

```rust
        self.pending_siginfo = Some(SigInfo {
            si_code: SI_USER,
            si_pid: self.pid,
            si_status: 0,
        });
        self.queue_signal(sig as u32);
```

- [ ] **Step 7: Update create_child to clear pending_siginfo**

In `create_child` (around line 6291), after `pending_handler_signal: None`:

```rust
            pending_handler_signal: None,
            pending_siginfo: None,
```

- [ ] **Step 8: Update apply_execve to clear pending_siginfo**

In `apply_execve` (around line 4335), after `self.pending_handler_signal = None`:

```rust
        self.pending_handler_signal = None;
        self.pending_siginfo = None;
```

- [ ] **Step 9: Write tests for SigInfo population**

```rust
    #[test]
    fn test_sigchld_siginfo_normal_exit() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Fork a child.
        let child_pid = lx.dispatch_syscall(LinuxSyscall::Fork) as i32;
        assert!(child_pid > 0);

        // Install SIGCHLD handler (custom, not SIG_DFL which ignores).
        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER | SA_SIGINFO;
        install_handler_with_restorer(&mut lx, SIGCHLD_NUM as i32, handler_addr, flags, 0, restorer_addr);

        // Child exits with code 42.
        if let Some((_pid, child_lx)) = lx.pending_fork_child() {
            child_lx.dispatch_syscall(LinuxSyscall::Exit { code: 42 });
        }

        // Parent dispatches any syscall to trigger recover_child_state + deliver_pending_signals.
        lx.dispatch_syscall(LinuxSyscall::Getpid);

        // SIGCHLD should be delivered to custom handler.
        let sig = lx.pending_handler_signal();
        assert_eq!(sig, Some(SIGCHLD_NUM), "SIGCHLD must be pending for custom handler");

        let info = lx.pending_siginfo();
        assert!(info.is_some(), "pending_siginfo must be set for SIGCHLD");
        let info = info.unwrap();
        assert_eq!(info.si_code, CLD_EXITED);
        assert_eq!(info.si_pid, child_pid);
        assert_eq!(info.si_status, 42);
    }

    #[test]
    fn test_sigchld_siginfo_killed_by_signal() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Fork a child.
        let child_pid = lx.dispatch_syscall(LinuxSyscall::Fork) as i32;
        assert!(child_pid > 0);

        // Install SIGCHLD handler.
        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER | SA_SIGINFO;
        install_handler_with_restorer(&mut lx, SIGCHLD_NUM as i32, handler_addr, flags, 0, restorer_addr);

        // Kill the child with SIGKILL.
        if let Some((_pid, child_lx)) = lx.pending_fork_child() {
            child_lx.dispatch_syscall(LinuxSyscall::Kill { pid: 0, sig: SIGKILL as i32 });
        }

        // Parent dispatches to trigger recovery.
        lx.dispatch_syscall(LinuxSyscall::Getpid);

        let sig = lx.pending_handler_signal();
        assert_eq!(sig, Some(SIGCHLD_NUM));

        let info = lx.pending_siginfo();
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.si_code, CLD_KILLED);
        assert_eq!(info.si_pid, child_pid);
        assert_eq!(info.si_status, SIGKILL as i32);
    }

    #[test]
    fn test_kill_siginfo_si_user() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Install custom handler for signal 10.
        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER | SA_SIGINFO;
        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, 0, restorer_addr);

        // Send signal 10 via kill.
        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 0, sig: 10 });

        let sig = lx.pending_handler_signal();
        assert_eq!(sig, Some(10));

        let info = lx.pending_siginfo();
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.si_code, SI_USER);
        assert_eq!(info.si_pid, 1); // default PID
        assert_eq!(info.si_status, 0);
    }
```

- [ ] **Step 10: Run tests**

Run: `cargo test -p harmony-os -- siginfo`
Expected: All 3 new tests pass.

- [ ] **Step 11: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat: SigInfo struct + pending_siginfo for SIGCHLD exit info"
```

---

### Task 3: aarch64 setup_signal_frame

**Context:** The existing `setup_signal_frame` builds an x86_64 signal frame (128-byte red zone, x86_64 sigcontext, retaddr on stack). We need an aarch64 version that builds the correct aarch64 `rt_sigframe`: siginfo_t at +0, ucontext with aarch64 sigcontext (regs[31]/sp/pc/pstate) and FPSIMD context in `__reserved`, restorer in x30, no red zone, 16-byte SP alignment. Also add the `siginfo: Option<&SigInfo>` parameter to both architectures.

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs:3096-3243` (cfg-gate existing, add aarch64 version)
- Modify: `crates/harmony-os/src/linuxulator.rs:17370-17870` (cfg-gate existing tests, add aarch64 tests)
- Test: `crates/harmony-os/src/linuxulator.rs`

**aarch64 frame layout reference (offsets from handler_sp):**
```
SIGINFO:       +0    (128 bytes) — si_signo(+0), si_code(+4), si_pid(+12), si_status(+16)
UCONTEXT:      +128  — uc_flags(+0), uc_link(+8), uc_stack(+16), uc_sigmask(+40), __unused(+48, 120 bytes)
SIGCONTEXT:    +296  — fault_address(+0), regs[31](+8), sp(+256), pc(+264), pstate(+272)
__RESERVED:    +584  — 8 bytes padding after pstate for __aligned__(16)
FPSIMD_CTX:    +584  — magic(+0 u32), size(+4 u32), fpsr(+8 u32), fpcr(+12 u32), vregs[32](+16, 512 bytes)
END_MARKER:    +1112 — magic=0(u32), size=0(u32)
FRAME_END:     +1120
```

- [ ] **Step 1: cfg-gate existing x86_64 setup_signal_frame**

Add `#[cfg(target_arch = "x86_64")]` to the existing `setup_signal_frame` method (line ~3096). Also add the `siginfo: Option<&SigInfo>` parameter:

```rust
    #[cfg(target_arch = "x86_64")]
    pub fn setup_signal_frame(
        &mut self,
        signum: u32,
        regs: &SavedRegisters,
        siginfo: Option<&SigInfo>,
    ) -> SignalHandlerSetup {
```

Inside the existing x86_64 `setup_signal_frame`, after writing `si_signo` to siginfo_t (line ~3158), add siginfo field writes:

```rust
        // si_signo at offset 0 of siginfo_t (i32).
        unsafe {
            core::ptr::write_unaligned(siginfo_ptr as *mut i32, signum as i32);
        }
        // Write additional siginfo fields if provided.
        if let Some(info) = siginfo {
            unsafe {
                core::ptr::write_unaligned((siginfo_ptr + 4) as *mut i32, info.si_code);
                core::ptr::write_unaligned((siginfo_ptr + 12) as *mut i32, info.si_pid);
                core::ptr::write_unaligned((siginfo_ptr + 16) as *mut i32, info.si_status);
            }
        }
```

- [ ] **Step 2: Add aarch64 setup_signal_frame**

Add the aarch64 version immediately after the x86_64 version:

```rust
    /// Build an aarch64 Linux-compatible signal frame on the user stack.
    ///
    /// Frame layout: siginfo_t(128) + ucontext_t (with sigcontext + FPSIMD).
    /// Restorer goes in x30 (LR), not on the stack.
    /// No red zone on aarch64. SP aligned to 16 bytes.
    #[cfg(target_arch = "aarch64")]
    pub fn setup_signal_frame(
        &mut self,
        signum: u32,
        regs: &SavedRegisters,
        siginfo: Option<&SigInfo>,
    ) -> SignalHandlerSetup {
        assert!(
            (1..=64).contains(&signum),
            "signum {signum} out of range [1, 64]"
        );
        let idx = (signum - 1) as usize;
        let action = self.signal_handlers[idx];

        assert!(
            action.flags & SA_RESTORER != 0,
            "SA_RESTORER must be set for signal handler invocation"
        );

        // ── Choose stack base ────────────────────────────────────────
        let was_on_alt_stack = self.on_alt_stack;
        let stack_top = if action.flags & SA_ONSTACK != 0
            && self.alt_stack_flags != SS_DISABLE
            && !self.on_alt_stack
        {
            self.on_alt_stack = true;
            self.alt_stack_sp + self.alt_stack_size
        } else {
            // No red zone on aarch64.
            regs.sp
        };

        // ── Compute frame pointer ───────────────────────────────────
        // Frame: 128 (siginfo) + 168 (ucontext header) + 280 (sigcontext regs)
        //      + 8 (alignment padding) + 528 (fpsimd) + 8 (end marker) = 1120 bytes.
        const FRAME_SIZE: u64 = 1120;
        let frame_base = stack_top - FRAME_SIZE;
        // Align down to 16 bytes (aarch64 ABI requirement).
        let handler_sp = frame_base & !0xF;

        let saved_mask = self.signal_mask;

        // ── Zero the frame ──────────────────────────────────────────
        unsafe {
            core::ptr::write_bytes(handler_sp as *mut u8, 0, FRAME_SIZE as usize);
        }

        // ── Offsets from handler_sp ─────────────────────────────────
        let siginfo_ptr = handler_sp;
        let ucontext_ptr = handler_sp + 128;
        let uc_stack_ptr = ucontext_ptr + 16;
        let uc_sigmask_ptr = ucontext_ptr + 40;
        let sc_ptr = ucontext_ptr + 168; // sigcontext
        let sc_regs_ptr = sc_ptr + 8; // regs[31] after fault_address
        let sc_sp_ptr = sc_ptr + 256;
        let sc_pc_ptr = sc_ptr + 264;
        let sc_pstate_ptr = sc_ptr + 272;
        // __reserved at sc_ptr + 288 (8-byte padding for __aligned__(16))
        let reserved_ptr = sc_ptr + 288;

        // ── Write siginfo_t ─────────────────────────────────────────
        unsafe {
            // si_signo at offset 0.
            core::ptr::write_unaligned(siginfo_ptr as *mut i32, signum as i32);
            if let Some(info) = siginfo {
                core::ptr::write_unaligned((siginfo_ptr + 4) as *mut i32, info.si_code);
                core::ptr::write_unaligned((siginfo_ptr + 12) as *mut i32, info.si_pid);
                core::ptr::write_unaligned((siginfo_ptr + 16) as *mut i32, info.si_status);
            }
        }

        // ── Write ucontext header ───────────────────────────────────
        // uc_flags and uc_link are zero (already zeroed).
        // uc_stack: save alt stack configuration.
        unsafe {
            core::ptr::write_unaligned(uc_stack_ptr as *mut u64, self.alt_stack_sp);
            core::ptr::write_unaligned(
                (uc_stack_ptr + 8) as *mut i32,
                self.alt_stack_flags | if was_on_alt_stack { SS_ONSTACK } else { 0 },
            );
            core::ptr::write_unaligned((uc_stack_ptr + 16) as *mut u64, self.alt_stack_size);
        }
        // uc_sigmask: saved signal mask.
        unsafe {
            core::ptr::write_unaligned(uc_sigmask_ptr as *mut u64, saved_mask);
        }

        // ── Write sigcontext ────────────────────────────────────────
        // fault_address at sc_ptr+0: zero (not a fault).
        // regs[31] at sc_ptr+8.
        unsafe {
            for i in 0..31 {
                core::ptr::write_unaligned(
                    (sc_regs_ptr + i as u64 * 8) as *mut u64,
                    regs.x[i],
                );
            }
            core::ptr::write_unaligned(sc_sp_ptr as *mut u64, regs.sp);
            core::ptr::write_unaligned(sc_pc_ptr as *mut u64, regs.pc);
            core::ptr::write_unaligned(sc_pstate_ptr as *mut u64, regs.pstate);
        }

        // ── Write FPSIMD context in __reserved ──────────────────────
        const FPSIMD_MAGIC: u32 = 0x46508001;
        const FPSIMD_SIZE: u32 = 528;
        unsafe {
            // Header: magic + size.
            core::ptr::write_unaligned(reserved_ptr as *mut u32, FPSIMD_MAGIC);
            core::ptr::write_unaligned((reserved_ptr + 4) as *mut u32, FPSIMD_SIZE);
            // fpsr and fpcr (u32 each, matching Linux's __u32 fields).
            core::ptr::write_unaligned((reserved_ptr + 8) as *mut u32, regs.fpsr as u32);
            core::ptr::write_unaligned((reserved_ptr + 12) as *mut u32, regs.fpcr as u32);
            // vregs[32]: 128-bit each.
            for i in 0..32 {
                core::ptr::write_unaligned(
                    (reserved_ptr + 16 + i as u64 * 16) as *mut u128,
                    regs.q[i],
                );
            }
            // End marker after FPSIMD context.
            let end_ptr = reserved_ptr + FPSIMD_SIZE as u64;
            core::ptr::write_unaligned(end_ptr as *mut u32, 0);
            core::ptr::write_unaligned((end_ptr + 4) as *mut u32, 0);
        }

        // ── Update signal mask for handler execution ────────────────
        self.signal_mask |= action.mask;
        if action.flags & SA_NODEFER == 0 {
            self.signal_mask |= 1u64 << (signum - 1);
        }
        self.signal_mask &= !(1u64 << (SIGKILL - 1));
        self.signal_mask &= !(1u64 << (SIGSTOP - 1));

        // ── SA_RESETHAND ────────────────────────────────────────────
        if action.flags & SA_RESETHAND != 0 {
            self.signal_handlers[idx].handler = SIG_DFL;
            self.signal_handlers[idx].flags = 0;
            self.signal_handlers[idx].mask = 0;
        }

        // ── Build return value ──────────────────────────────────────
        let (x1, x2) = if action.flags & SA_SIGINFO != 0 {
            (siginfo_ptr, ucontext_ptr)
        } else {
            (0, 0)
        };

        SignalHandlerSetup {
            handler_pc: action.handler,
            handler_sp,
            x0: signum as u64,
            x1,
            x2,
            x30: action.restorer,
        }
    }
```

- [ ] **Step 3: cfg-gate existing x86_64 signal frame tests**

Add `#[cfg(target_arch = "x86_64")]` to each of the existing tests that use x86_64 SavedRegisters fields:

- `test_setup_signal_frame_basic` (line ~17407)
- `test_signal_mask_blocks_during_handler` (line ~17474)
- `test_sa_nodefer` (line ~17533)
- `test_sa_resethand` (line ~17583)
- `test_sigreturn_restores_registers` (line ~17638)
- `test_sigreturn_restores_signal_mask` (line ~17714)
- `test_sigreturn_delivers_unblocked` (line ~17807)

And any alt-stack tests that use x86_64 SavedRegisters. For each, add:
```rust
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_setup_signal_frame_basic() {
```

Also update calls to `setup_signal_frame` in x86_64 tests to pass `None` for the new `siginfo` parameter:
```rust
        let setup = lx.setup_signal_frame(10, &regs, None);
```

- [ ] **Step 4: Write aarch64 signal frame tests**

```rust
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_setup_signal_frame_basic_aarch64() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER | SA_SIGINFO;

        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, 0, restorer_addr);

        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        let sig = lx.pending_handler_signal();
        assert_eq!(sig, Some(10));
        let _ = lx.pending_siginfo(); // consume

        let sp = (lx.arena_base() + 0x50000) as u64;
        let regs = SavedRegisters {
            x: {
                let mut x = [0u64; 31];
                x[0] = 0xA0;
                x[1] = 0xA1;
                x[29] = 0xFB;
                x[30] = 0xAE; // will be overwritten by setup
                x
            },
            sp,
            pc: 0x1000,
            pstate: 0x600003C5,
            fpcr: 0x42,
            fpsr: 0x43,
            q: {
                let mut q = [0u128; 32];
                q[0] = 0xDEAD_BEEF;
                q[31] = 0xCAFE_BABE;
                q
            },
        };

        let info = SigInfo { si_code: CLD_EXITED, si_pid: 5, si_status: 42 };
        let setup = lx.setup_signal_frame(10, &regs, Some(&info));

        // handler_pc must equal the installed handler address.
        assert_eq!(setup.handler_pc, handler_addr);

        // x0 = signal number.
        assert_eq!(setup.x0, 10);

        // x30 = restorer.
        assert_eq!(setup.x30, restorer_addr);

        // SA_SIGINFO: x1 (siginfo) and x2 (ucontext) must be non-zero.
        assert_ne!(setup.x1, 0, "x1 (siginfo_t) must be non-zero for SA_SIGINFO");
        assert_ne!(setup.x2, 0, "x2 (ucontext_t) must be non-zero for SA_SIGINFO");

        // handler_sp must be 16-byte aligned.
        assert_eq!(setup.handler_sp % 16, 0, "handler_sp must be 16-byte aligned");

        // Verify siginfo_t fields.
        let frame = setup.handler_sp;
        unsafe {
            assert_eq!(core::ptr::read_unaligned(frame as *const i32), 10, "si_signo");
            assert_eq!(core::ptr::read_unaligned((frame + 4) as *const i32), CLD_EXITED, "si_code");
            assert_eq!(core::ptr::read_unaligned((frame + 12) as *const i32), 5, "si_pid");
            assert_eq!(core::ptr::read_unaligned((frame + 16) as *const i32), 42, "si_status");
        }

        // Verify sigcontext regs.
        let sc_regs = frame + 296 + 8; // sigcontext.regs[0]
        unsafe {
            assert_eq!(core::ptr::read_unaligned(sc_regs as *const u64), 0xA0, "regs[0]");
            assert_eq!(core::ptr::read_unaligned((sc_regs + 8) as *const u64), 0xA1, "regs[1]");
        }

        // Verify sp/pc/pstate in sigcontext.
        unsafe {
            assert_eq!(core::ptr::read_unaligned((frame + 296 + 256) as *const u64), sp, "sc.sp");
            assert_eq!(core::ptr::read_unaligned((frame + 296 + 264) as *const u64), 0x1000, "sc.pc");
            assert_eq!(core::ptr::read_unaligned((frame + 296 + 272) as *const u64), 0x600003C5, "sc.pstate");
        }

        // Verify FPSIMD context.
        let reserved = frame + 296 + 288;
        unsafe {
            assert_eq!(core::ptr::read_unaligned(reserved as *const u32), 0x46508001, "FPSIMD_MAGIC");
            assert_eq!(core::ptr::read_unaligned((reserved + 4) as *const u32), 528, "FPSIMD size");
            assert_eq!(core::ptr::read_unaligned((reserved + 8) as *const u32), 0x43, "fpsr");
            assert_eq!(core::ptr::read_unaligned((reserved + 12) as *const u32), 0x42, "fpcr");
            assert_eq!(core::ptr::read_unaligned((reserved + 16) as *const u128), 0xDEAD_BEEF, "vregs[0]");
            assert_eq!(core::ptr::read_unaligned((reserved + 16 + 31 * 16) as *const u128), 0xCAFE_BABE, "vregs[31]");
        }

        // Verify end marker.
        unsafe {
            let end = reserved + 528;
            assert_eq!(core::ptr::read_unaligned(end as *const u32), 0, "end magic");
            assert_eq!(core::ptr::read_unaligned((end + 4) as *const u32), 0, "end size");
        }

        // Verify uc_sigmask.
        unsafe {
            assert_eq!(core::ptr::read_unaligned((frame + 128 + 40) as *const u64), 0, "saved mask (was 0)");
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_signal_mask_blocks_during_handler_aarch64() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER | SA_SIGINFO;
        let sa_mask: u64 = 1u64 << 11; // Block signal 12.

        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, sa_mask, restorer_addr);

        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        let sig = lx.pending_handler_signal();
        assert_eq!(sig, Some(10));
        let _ = lx.pending_siginfo();

        let sp = (lx.arena_base() + 0x50000) as u64;
        let regs = SavedRegisters { sp, ..SavedRegisters::default() };
        let _setup = lx.setup_signal_frame(10, &regs, None);

        let mask = read_signal_mask(&mut lx);
        // Signal 10 (bit 9) blocked (no SA_NODEFER).
        assert_ne!(mask & (1u64 << 9), 0, "signal 10 should be blocked during handler");
        // Signal 12 (bit 11) blocked via sa_mask.
        assert_ne!(mask & (1u64 << 11), 0, "signal 12 should be blocked via sa_mask");
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_sa_resethand_aarch64() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER | SA_SIGINFO | SA_RESETHAND;

        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, 0, restorer_addr);

        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        let _ = lx.pending_handler_signal();
        let _ = lx.pending_siginfo();

        let sp = (lx.arena_base() + 0x50000) as u64;
        let regs = SavedRegisters { sp, ..SavedRegisters::default() };
        let _setup = lx.setup_signal_frame(10, &regs, None);

        // Handler should be reset to SIG_DFL.
        let mut oldact = [0u8; 32];
        lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: 0,
            oldact: oldact.as_mut_ptr() as u64,
            sigsetsize: 8,
        });
        assert_eq!(read_handler(&oldact), SIG_DFL, "handler must be reset after SA_RESETHAND");
    }
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p harmony-os -- signal_frame`
Expected: On aarch64 host — 3 new aarch64 tests pass, x86_64 tests skipped. On x86_64 host — existing tests pass (with new `None` siginfo param), aarch64 tests skipped.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat: aarch64 setup_signal_frame with FPSIMD + siginfo fields"
```

---

### Task 4: aarch64 sys_rt_sigreturn

**Context:** The existing `sys_rt_sigreturn` reads an x86_64 signal frame (ucontext at RSP+0 after retaddr pop, x86_64 sigcontext layout). The aarch64 version reads the frame from SP directly (no retaddr pop): siginfo at SP+0, ucontext at SP+128, sigcontext at SP+296, FPSIMD in __reserved. Must also restore FPSIMD state (fpcr, fpsr, q[0-31]).

**Frame offsets for aarch64 rt_sigreturn (from SP):**
```
UCONTEXT:    +128
UC_STACK:    +128+16 = +144   (ss_flags at +8 within uc_stack = +152)
UC_SIGMASK:  +128+40 = +168
SIGCONTEXT:  +128+168 = +296
SC_REGS:     +296+8 = +304    (regs[31], 248 bytes)
SC_SP:       +296+256 = +552
SC_PC:       +296+264 = +560
SC_PSTATE:   +296+272 = +568
RESERVED:    +296+288 = +584
FPSIMD:      +584              (magic, size, fpsr, fpcr, vregs)
```

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs:7720-7778` (cfg-gate existing, add aarch64 version)
- Test: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: cfg-gate existing x86_64 sys_rt_sigreturn**

Add `#[cfg(target_arch = "x86_64")]` to the existing `sys_rt_sigreturn` (line ~7734):

```rust
    #[cfg(target_arch = "x86_64")]
    fn sys_rt_sigreturn(&mut self, rsp: u64) -> i64 {
```

- [ ] **Step 2: Add aarch64 sys_rt_sigreturn**

```rust
    /// aarch64 rt_sigreturn: restore register state and signal mask from the
    /// aarch64 signal frame on the user stack.
    ///
    /// Frame layout from SP (no retaddr pop on aarch64):
    ///   +0:   siginfo_t (128 bytes)
    ///   +128: ucontext_t:
    ///         ├─ uc_flags/uc_link/uc_stack (40 bytes)
    ///         ├─ uc_sigmask (8 bytes)
    ///         ├─ __unused (120 bytes)
    ///         └─ sigcontext at +168:
    ///            ├─ fault_address(8), regs[31](248), sp(8), pc(8), pstate(8)
    ///            └─ __reserved at +288: fpsimd_context(528) + end_marker(8)
    #[cfg(target_arch = "aarch64")]
    fn sys_rt_sigreturn(&mut self, rsp: u64) -> i64 {
        // On aarch64, SP points directly at the signal frame (no retaddr pop).
        let frame = rsp;
        let ucontext_ptr = frame + 128;
        let sc_ptr = ucontext_ptr + 168; // sigcontext within ucontext
        let sc_regs_ptr = sc_ptr + 8; // regs[31] after fault_address

        // Restore GPRs: regs[0..31] from sigcontext.
        let mut x = [0u64; 31];
        unsafe {
            for i in 0..31 {
                x[i] = core::ptr::read_unaligned((sc_regs_ptr + i as u64 * 8) as *const u64);
            }
        }

        let sp = unsafe { core::ptr::read_unaligned((sc_ptr + 256) as *const u64) };
        let pc = unsafe { core::ptr::read_unaligned((sc_ptr + 264) as *const u64) };
        let pstate = unsafe { core::ptr::read_unaligned((sc_ptr + 272) as *const u64) };

        // Restore FPSIMD from __reserved (at sigcontext + 288).
        let reserved_ptr = sc_ptr + 288;
        let magic = unsafe { core::ptr::read_unaligned(reserved_ptr as *const u32) };
        let (fpsr, fpcr, q) = if magic == 0x46508001 {
            // FPSIMD_MAGIC found — restore FP state.
            let fpsr = unsafe { core::ptr::read_unaligned((reserved_ptr + 8) as *const u32) } as u64;
            let fpcr = unsafe { core::ptr::read_unaligned((reserved_ptr + 12) as *const u32) } as u64;
            let mut q = [0u128; 32];
            unsafe {
                for i in 0..32 {
                    q[i] = core::ptr::read_unaligned(
                        (reserved_ptr + 16 + i as u64 * 16) as *const u128,
                    );
                }
            }
            (fpsr, fpcr, q)
        } else {
            // No FPSIMD context — leave FP state zeroed.
            (0, 0, [0u128; 32])
        };

        let regs = SavedRegisters {
            x,
            sp,
            pc,
            pstate,
            fpcr,
            fpsr,
            q,
        };

        // Restore signal mask from uc_sigmask (at ucontext + 40).
        let uc_sigmask = unsafe { core::ptr::read_unaligned((ucontext_ptr + 40) as *const u64) };
        self.signal_mask = uc_sigmask;
        self.signal_mask &= !(1u64 << (SIGKILL - 1) | 1u64 << (SIGSTOP - 1));

        // Restore on_alt_stack from saved uc_stack.ss_flags.
        let saved_ss_flags =
            unsafe { core::ptr::read_unaligned((ucontext_ptr + 24) as *const i32) };
        self.on_alt_stack = saved_ss_flags & SS_ONSTACK != 0;

        self.pending_signal_return = Some(SignalReturn { regs });

        // Return value is meaningless — caller uses pending_signal_return().
        regs.x[0] as i64
    }
```

- [ ] **Step 3: Write aarch64 sigreturn tests**

```rust
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_sigreturn_restores_registers_aarch64() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER | SA_SIGINFO;
        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, 0, restorer_addr);

        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        let _ = lx.pending_handler_signal();
        let _ = lx.pending_siginfo();

        let sp = (lx.arena_base() + 0x50000) as u64;
        let regs = SavedRegisters {
            x: {
                let mut x = [0u64; 31];
                x[0] = 0x0A0A_0A0A;
                x[1] = 0x0B0B_0B0B;
                x[29] = 0xFBFB_FBFB;
                x[30] = 0xAEAE_AEAE; // LR
                x
            },
            sp,
            pc: 0x1000_2000,
            pstate: 0x600003C5,
            fpcr: 0x42,
            fpsr: 0x43,
            q: {
                let mut q = [0u128; 32];
                q[0] = 0xDEAD;
                q[31] = 0xBEEF;
                q
            },
        };

        let setup = lx.setup_signal_frame(10, &regs, None);

        // On aarch64: SP at handler_sp, no retaddr pop. sigreturn receives SP directly.
        let sigreturn_sp = setup.handler_sp;
        lx.dispatch_syscall(LinuxSyscall::RtSigreturn { rsp: sigreturn_sp });

        let sr = lx.pending_signal_return();
        assert!(sr.is_some(), "pending_signal_return must be Some after sigreturn");
        let restored = sr.unwrap().regs;

        assert_eq!(restored.x[0], 0x0A0A_0A0A, "x0");
        assert_eq!(restored.x[1], 0x0B0B_0B0B, "x1");
        assert_eq!(restored.x[29], 0xFBFB_FBFB, "x29 (FP)");
        assert_eq!(restored.sp, sp, "SP");
        assert_eq!(restored.pc, 0x1000_2000, "PC");
        assert_eq!(restored.pstate, 0x600003C5, "PSTATE");
        assert_eq!(restored.fpcr, 0x42, "FPCR");
        assert_eq!(restored.fpsr, 0x43, "FPSR");
        assert_eq!(restored.q[0], 0xDEAD, "Q0");
        assert_eq!(restored.q[31], 0xBEEF, "Q31");
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_sigreturn_restores_signal_mask_aarch64() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER | SA_SIGINFO;
        let sa_mask: u64 = 1u64 << 13; // Block signal 14 during handler.

        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, sa_mask, restorer_addr);

        // Pre-block signal 12 (bit 11).
        let pre_block: u64 = 1u64 << 11;
        let pre_block_bytes = pre_block.to_ne_bytes();
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: pre_block_bytes.as_ptr() as u64,
            oldset: 0,
            sigsetsize: 8,
        });

        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        let _ = lx.pending_handler_signal();
        let _ = lx.pending_siginfo();

        let sp = (lx.arena_base() + 0x50000) as u64;
        let regs = SavedRegisters { sp, ..SavedRegisters::default() };
        let setup = lx.setup_signal_frame(10, &regs, None);

        // During handler: 10 (bit 9) + 12 (bit 11) + 14 (bit 13) blocked.
        let mask_during = read_signal_mask(&mut lx);
        assert_ne!(mask_during & (1u64 << 9), 0, "signal 10 blocked during handler");
        assert_ne!(mask_during & (1u64 << 11), 0, "signal 12 still blocked");
        assert_ne!(mask_during & (1u64 << 13), 0, "signal 14 blocked via sa_mask");

        // Sigreturn.
        lx.dispatch_syscall(LinuxSyscall::RtSigreturn { rsp: setup.handler_sp });
        let _ = lx.pending_signal_return();

        // After: only 12 (bit 11) should be blocked.
        let mask_after = read_signal_mask(&mut lx);
        assert_eq!(mask_after & (1u64 << 9), 0, "signal 10 unblocked after sigreturn");
        assert_ne!(mask_after & (1u64 << 11), 0, "signal 12 still blocked (was pre-blocked)");
        assert_eq!(mask_after & (1u64 << 13), 0, "signal 14 unblocked (was only in sa_mask)");
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_sigreturn_delivers_unblocked_aarch64() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let handler_addr: u64 = 0x400000;
        let restorer_addr: u64 = 0x401000;
        let flags = SA_RESTORER | SA_SIGINFO;
        install_handler_with_restorer(&mut lx, 10, handler_addr, flags, 0, restorer_addr);

        // First kill: triggers signal 10.
        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });
        let _ = lx.pending_handler_signal();
        let _ = lx.pending_siginfo();

        let sp = (lx.arena_base() + 0x50000) as u64;
        let regs = SavedRegisters { sp, ..SavedRegisters::default() };
        let setup = lx.setup_signal_frame(10, &regs, None);

        // Signal 10 blocked during handler. Queue another signal 10.
        lx.dispatch_syscall(LinuxSyscall::Kill { pid: 1, sig: 10 });

        // Sigreturn unblocks signal 10 → deliver_pending_signals fires.
        lx.dispatch_syscall(LinuxSyscall::RtSigreturn { rsp: setup.handler_sp });
        let _ = lx.pending_signal_return();

        // The queued signal 10 should now be delivered.
        let sig = lx.pending_handler_signal();
        assert_eq!(sig, Some(10), "queued signal must be delivered after sigreturn unblocks it");
    }
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p harmony-os -- sigreturn`
Expected: On aarch64 host — 3 new tests pass, x86_64 tests skipped. On x86_64 host — existing tests pass, aarch64 tests skipped.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat: aarch64 sys_rt_sigreturn with FPSIMD restore"
```

---

### Task 5: Boot Code Wiring — dispatch() + svc_handler Signal Delivery

**Context:** The linuxulator can now build aarch64 signal frames and restore from them. The boot code needs to: (1) intercept syscall nr 139 (rt_sigreturn) and construct the RtSigreturn variant with SP_EL0, (2) extend SyscallDispatchResult with signal fields, (3) check pending_handler_signal/pending_signal_return after each dispatch, (4) patch TrapFrame in svc_handler for signal delivery and return. This task is aarch64-only (boot crate).

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/syscall.rs:38-44` (SyscallDispatchResult)
- Modify: `crates/harmony-boot-aarch64/src/syscall.rs:141-237` (svc_handler)
- Modify: `crates/harmony-boot-aarch64/src/main.rs:557-604` (dispatch)
- Test: Cross-compile verification only (no host-side tests for boot crate)

- [ ] **Step 1: Add SP_EL0 helpers to syscall.rs**

Add after `current_trapframe()` (line ~77):

```rust
/// Read the user-space stack pointer (SP_EL0).
///
/// # Safety
/// Must only be called from within the SVC handler path (EL1, IRQs masked).
#[cfg(target_arch = "aarch64")]
pub unsafe fn read_sp_el0() -> u64 {
    let sp: u64;
    core::arch::asm!("mrs {}, sp_el0", out(reg) sp);
    sp
}

/// Write the user-space stack pointer (SP_EL0).
///
/// # Safety
/// Must only be called from within the SVC handler path (EL1, IRQs masked).
#[cfg(target_arch = "aarch64")]
pub unsafe fn write_sp_el0(val: u64) {
    core::arch::asm!("msr sp_el0, {}", in(reg) val);
}
```

- [ ] **Step 2: Extend SyscallDispatchResult**

Update the struct (line ~38):

```rust
/// Result from syscall dispatch.
pub struct SyscallDispatchResult {
    pub retval: i64,
    pub exited: bool,
    pub exit_code: i32,
    /// True for exit_group (kill all threads), false for thread-only exit.
    pub exit_group: bool,
    /// Signal handler to invoke — svc_handler patches TrapFrame to jump here.
    pub signal_setup: Option<harmony_os::linuxulator::SignalHandlerSetup>,
    /// Register state to restore after rt_sigreturn.
    pub signal_return: Option<harmony_os::linuxulator::SavedRegisters>,
}
```

- [ ] **Step 3: Handle rt_sigreturn (nr 139) in svc_handler**

In `svc_handler` (line ~150), intercept nr 139 before calling `from_aarch64`:

```rust
    let syscall = if nr == 139 {
        // rt_sigreturn takes no register arguments — the kernel reads SP
        // from the saved process state. Construct the variant manually.
        LinuxSyscall::RtSigreturn { rsp: read_sp_el0() }
    } else {
        LinuxSyscall::from_aarch64(nr, args)
    };
```

- [ ] **Step 4: Update dispatch() to check pending signals**

In the `dispatch` function (line ~557), after the existing exit/non-exit paths, add signal checks. The non-exit path becomes:

```rust
            } else {
                // ── Signal delivery check ───────────────────────────
                // After each syscall, check if a signal handler needs
                // invocation or if rt_sigreturn restored registers.

                // Check signal return first (rt_sigreturn restores registers).
                let signal_return_regs = lx.pending_signal_return().map(|sr| sr.regs);

                // Check for pending signal handler.
                let signal_setup = if let Some(signum) = lx.pending_handler_signal() {
                    let siginfo = lx.pending_siginfo();
                    // Build SavedRegisters from the current state. If sigreturn
                    // just happened, use restored regs (not TrapFrame, which
                    // still has the pre-sigreturn state).
                    let saved = if let Some(ref regs) = signal_return_regs {
                        let mut r = *regs;
                        // The syscall retval goes in x[0]. For sigreturn, the
                        // retval is whatever was in saved x[0] — already correct.
                        r
                    } else {
                        // Snapshot current TrapFrame.
                        let frame = unsafe { &*syscall::current_trapframe() };
                        let sp = unsafe { syscall::read_sp_el0() };
                        use harmony_os::linuxulator::SavedRegisters;
                        let mut r = SavedRegisters {
                            x: frame.x,
                            sp,
                            pc: frame.elr,
                            pstate: frame.spsr,
                            fpcr: frame.fpcr,
                            fpsr: frame.fpsr,
                            q: frame.q,
                        };
                        // Include syscall return value in x[0] — this is
                        // what the interrupted code would see if there were
                        // no signal. The signal frame saves it, and sigreturn
                        // restores it when the handler finishes.
                        r.x[0] = retval as u64;
                        r
                    };
                    Some(lx.setup_signal_frame(signum, &saved, siginfo.as_ref()))
                } else {
                    None
                };

                // If both signal_return and signal_setup, only setup matters —
                // restored regs were consumed as input to setup_signal_frame.
                let signal_return = if signal_setup.is_some() {
                    None
                } else {
                    signal_return_regs
                };

                syscall::SyscallDispatchResult {
                    retval,
                    exited: false,
                    exit_code: 0,
                    exit_group: false,
                    signal_setup,
                    signal_return,
                }
            }
```

Also update the exit paths to include `signal_setup: None, signal_return: None` in the SyscallDispatchResult returned from the `if is_exit || is_exit_group` branch.

- [ ] **Step 5: Add TrapFrame patching to svc_handler**

In `svc_handler`, after writing retval to `frame.x[0]` (line ~232) and before the closing `}` of the dispatch block, add signal handling:

```rust
        // ── Signal delivery ──────────────────────────────────────
        if let Some(setup) = result.signal_setup {
            frame.elr = setup.handler_pc;
            frame.x[0] = setup.x0;   // signum
            frame.x[1] = setup.x1;   // siginfo_t pointer
            frame.x[2] = setup.x2;   // ucontext_t pointer
            frame.x[30] = setup.x30; // LR = restorer
            write_sp_el0(setup.handler_sp);
            return; // Skip writing retval to x[0] — already set to signum.
        } else if let Some(regs) = result.signal_return {
            frame.x = regs.x;
            frame.elr = regs.pc;
            frame.spsr = regs.pstate;
            frame.fpcr = regs.fpcr;
            frame.fpsr = regs.fpsr;
            frame.q = regs.q;
            write_sp_el0(regs.sp);
            return; // Skip writing retval — registers fully restored.
        }
        frame.x[0] = result.retval as u64;
```

Note: the existing `frame.x[0] = result.retval as u64;` line (line ~232) moves inside the else (or is replaced by the new pattern above where it's at the end after the signal checks).

- [ ] **Step 6: Verify cross-compilation**

Run: `cargo clippy --workspace`
Expected: Clean. The new signal fields use types from `harmony_os::linuxulator` which the boot crate already depends on.

Run: `cargo test --workspace`
Expected: All linuxulator tests pass. Boot crate compiles cleanly.

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-boot-aarch64/src/syscall.rs crates/harmony-boot-aarch64/src/main.rs
git commit -m "feat: wire signal delivery into boot code dispatch + svc_handler"
```

---

## Verification Checklist

After all tasks:

1. `cargo test --workspace` — all tests pass
2. `cargo clippy --workspace` — no warnings
3. Signal delivery flow: queue_signal → deliver_pending_signals → pending_handler_signal → setup_signal_frame → dispatch() → svc_handler TrapFrame patch → eret to handler → ret to restorer → svc rt_sigreturn → sys_rt_sigreturn → pending_signal_return → dispatch() → svc_handler restore → eret to interrupted code
4. SIGCHLD flow: child exits → recover_child_state → pending_signals |= SIGCHLD + pending_siginfo set → deliver_pending_signals → if custom handler: setup frame with siginfo (si_code, si_pid, si_status)
5. x86_64 code preserved: all existing x86_64 signal tests still pass on x86_64 hosts
