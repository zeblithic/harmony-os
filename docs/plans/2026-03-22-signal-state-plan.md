# Signal State Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace rt_sigaction and rt_sigprocmask stubs with real per-process signal state tracking — handler table and blocked mask.

**Architecture:** New `SignalAction` struct stored in a 64-element array on `Linuxulator`. `rt_sigaction` reads/writes handler entries using platform-specific struct layouts. `rt_sigprocmask` manages a u64 bitmask with SIG_BLOCK/SIG_UNBLOCK/SIG_SETMASK operations. Signal state is cloned on fork, handlers reset on execve, mask preserved on execve.

**Tech Stack:** Rust, `no_std` (`alloc` only), platform-specific `#[cfg(target_arch)]` for struct sigaction layout

**Spec:** `docs/specs/2026-03-22-signal-state-design.md`

---

## File Structure

All changes in a single file:

| File | Responsibility |
|------|---------------|
| Modify: `crates/harmony-os/src/linuxulator.rs` | SignalAction struct, signal constants, Linuxulator +2 fields, LinuxSyscall variant fields, syscall table updates, sys_rt_sigaction + sys_rt_sigprocmask implementations, create_child + reset_for_execve integration, 14 tests |

---

### Task 1: Data structures + constants + LinuxSyscall field updates

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Add signal constants**

After the existing errno/clock/fd constants (~line 45), add:

```rust
// Signal constants
const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;
const SIGKILL: u32 = 9;
const SIGSTOP: u32 = 19;
const SIG_BLOCK: i32 = 0;
const SIG_UNBLOCK: i32 = 1;
const SIG_SETMASK: i32 = 2;
```

- [ ] **Step 2: Add SignalAction struct**

After `EpollState` struct (~line 1596):

```rust
/// Per-signal handler disposition, stored in a 64-element array.
#[derive(Clone, Copy)]
struct SignalAction {
    /// SIG_DFL (0), SIG_IGN (1), or handler function pointer.
    handler: u64,
    /// Signals to block during handler execution.
    mask: u64,
    /// Flags: SA_RESTART, SA_SIGINFO, SA_NOCLDSTOP, etc.
    flags: u64,
}

impl Default for SignalAction {
    fn default() -> Self {
        Self {
            handler: SIG_DFL,
            mask: 0,
            flags: 0,
        }
    }
}
```

- [ ] **Step 3: Add signal fields to Linuxulator struct**

Before the closing brace of the struct (~line 1741):

```rust
    /// Per-signal handler disposition (signals 1-64, index 0 = signal 1).
    signal_handlers: [SignalAction; 64],
    /// Blocked signal mask (bit N = signal N+1 is blocked).
    signal_mask: u64,
```

- [ ] **Step 4: Initialize in with_arena**

Before the closing brace of `with_arena` (~line 1779):

```rust
            signal_handlers: [SignalAction::default(); 64],
            signal_mask: 0,
```

- [ ] **Step 5: Add to create_child**

In the child struct literal in `create_child` (~line 3391, before the closing brace):

```rust
            signal_handlers: self.signal_handlers,
            signal_mask: self.signal_mask,
```

- [ ] **Step 6: Add to reset_for_execve**

In `reset_for_execve` (~line 2522, before the closing brace):

```rust
        // Reset all signal handlers to SIG_DFL on exec (Linux semantics).
        // Signal mask is preserved across exec.
        self.signal_handlers = [SignalAction::default(); 64];
```

- [ ] **Step 7: Update LinuxSyscall variants**

Replace the fieldless variants (~lines 131-132):

```rust
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
```

- [ ] **Step 8: Update x86_64 syscall table**

Replace nr 13 and 14 (~lines 446-447):

```rust
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
```

- [ ] **Step 9: Update aarch64 syscall table**

Replace nr 134 and 135 (~lines 872-873):

```rust
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
```

- [ ] **Step 10: Update dispatch_syscall match arms**

Replace the dispatch arms (~lines 2063-2064):

```rust
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
```

- [ ] **Step 11: Update sys_rt_sigaction and sys_rt_sigprocmask signatures**

Replace the stubs (~lines 4123-4131) with stubs that accept the new parameters but still return 0 (implementations come in Task 2):

```rust
    /// Linux rt_sigaction(2): register signal handler.
    fn sys_rt_sigaction(&mut self, _signum: i32, _act: u64, _oldact: u64, _sigsetsize: u64) -> i64 {
        0 // stub — implemented in Task 2
    }

    /// Linux rt_sigprocmask(2): manage blocked signal mask.
    fn sys_rt_sigprocmask(&mut self, _how: i32, _set: u64, _oldset: u64, _sigsetsize: u64) -> i64 {
        0 // stub — implemented in Task 2
    }
```

- [ ] **Step 12: Run tests, clippy, fmt**

Run: `cargo test -p harmony-os 2>&1 | tail -10`
Run: `cargo clippy -p harmony-os -- -D warnings 2>&1 | tail -10`
Run: `cargo fmt --all -- --check`

Note: Some signal constants may need `#[allow(dead_code)]` until Task 2 uses them.

- [ ] **Step 13: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add signal state structures, update LinuxSyscall variants for rt_sigaction/rt_sigprocmask"
```

---

### Task 2: sys_rt_sigaction + sys_rt_sigprocmask implementations

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Implement sys_rt_sigaction**

Replace the stub:

```rust
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
        if signum < 1 || signum > 64 {
            return EINVAL;
        }
        if signum == SIGKILL as i32 || signum == SIGSTOP as i32 {
            return EINVAL;
        }

        let idx = (signum - 1) as usize;

        // Write current handler to oldact if requested.
        if oldact_ptr != 0 {
            let action = &self.signal_handlers[idx];
            Self::write_sigaction(oldact_ptr, action);
        }

        // Read and store new handler if provided.
        if act_ptr != 0 {
            self.signal_handlers[idx] = Self::read_sigaction(act_ptr);
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
        let mask_offset = 24; // skip sa_restorer at offset 16
        #[cfg(target_arch = "aarch64")]
        let mask_offset = 16;
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
        }
    }

    /// Write a kernel sigaction struct to user memory.
    fn write_sigaction(ptr: u64, action: &SignalAction) {
        let addr = ptr as usize;
        unsafe {
            core::slice::from_raw_parts_mut(addr as *mut u8, 8)
        }
        .copy_from_slice(&action.handler.to_ne_bytes());
        unsafe {
            core::slice::from_raw_parts_mut((addr + 8) as *mut u8, 8)
        }
        .copy_from_slice(&action.flags.to_ne_bytes());

        #[cfg(target_arch = "x86_64")]
        {
            // Write 0 for sa_restorer at offset 16.
            unsafe {
                core::slice::from_raw_parts_mut((addr + 16) as *mut u8, 8)
            }
            .copy_from_slice(&0u64.to_ne_bytes());
        }

        #[cfg(target_arch = "x86_64")]
        let mask_offset = 24;
        #[cfg(target_arch = "aarch64")]
        let mask_offset = 16;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let mask_offset = 16;

        unsafe {
            core::slice::from_raw_parts_mut((addr + mask_offset) as *mut u8, 8)
        }
        .copy_from_slice(&action.mask.to_ne_bytes());
    }
```

- [ ] **Step 2: Implement sys_rt_sigprocmask**

Replace the stub:

```rust
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

        // Write old mask before modifying.
        if oldset_ptr != 0 {
            let buf = unsafe {
                core::slice::from_raw_parts_mut(oldset_ptr as usize as *mut u8, 8)
            };
            buf.copy_from_slice(&self.signal_mask.to_ne_bytes());
        }

        // Apply new mask if provided.
        if set_ptr != 0 {
            let set_bytes = unsafe {
                core::slice::from_raw_parts(set_ptr as usize as *const u8, 8)
            };
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

        0
    }
```

- [ ] **Step 3: Remove dead_code allows on signal constants**

If Task 1 added `#[allow(dead_code)]` to any signal constants, remove them now.

- [ ] **Step 4: Run tests, clippy, fmt**

Run: `cargo test -p harmony-os 2>&1 | tail -10`
Run: `cargo clippy -p harmony-os -- -D warnings 2>&1 | tail -10`
Run: `cargo fmt --all -- --check`

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): implement sys_rt_sigaction and sys_rt_sigprocmask with real state tracking"
```

---

### Task 3: All 14 tests

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Add sigaction struct size constant for tests**

In `mod tests`, add:

```rust
    /// Size of kernel sigaction struct: 32 bytes on x86_64, 24 on aarch64.
    #[cfg(target_arch = "x86_64")]
    const SIGACTION_SIZE: usize = 32;
    #[cfg(target_arch = "aarch64")]
    const SIGACTION_SIZE: usize = 24;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const SIGACTION_SIZE: usize = 24;
```

- [ ] **Step 2: Add all 14 tests**

Add at end of `mod tests`:

```rust
    // ── Signal tests ──────────────────────────────────────────────

    #[test]
    fn test_sigaction_set_and_get() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Set a handler for SIGUSR1 (signal 10)
        let mut act = [0u8; SIGACTION_SIZE];
        // sa_handler = 0x400000 (function pointer)
        act[0..8].copy_from_slice(&0x400000u64.to_ne_bytes());
        // sa_flags = 0x04000000 (SA_SIGINFO)
        act[8..16].copy_from_slice(&0x04000000u64.to_ne_bytes());
        // sa_mask at platform-specific offset
        #[cfg(target_arch = "x86_64")]
        act[24..32].copy_from_slice(&0x0000FFFFu64.to_ne_bytes());
        #[cfg(not(target_arch = "x86_64"))]
        act[16..24].copy_from_slice(&0x0000FFFFu64.to_ne_bytes());

        let r = lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10, // SIGUSR1
            act: act.as_ptr() as u64,
            oldact: 0,
            sigsetsize: 8,
        });
        assert_eq!(r, 0);

        // Read it back
        let mut oldact = [0u8; SIGACTION_SIZE];
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: 0,
            oldact: oldact.as_mut_ptr() as u64,
            sigsetsize: 8,
        });
        assert_eq!(r, 0);

        // Verify handler
        let handler = u64::from_ne_bytes(oldact[0..8].try_into().unwrap());
        assert_eq!(handler, 0x400000);
        // Verify flags
        let flags = u64::from_ne_bytes(oldact[8..16].try_into().unwrap());
        assert_eq!(flags, 0x04000000);
    }

    #[test]
    fn test_sigaction_reject_sigkill() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let act = [0u8; SIGACTION_SIZE];
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 9, // SIGKILL
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

        let act = [0u8; SIGACTION_SIZE];
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 19, // SIGSTOP
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

        // First set a handler
        let mut act = [0u8; SIGACTION_SIZE];
        act[0..8].copy_from_slice(&0xBEEFu64.to_ne_bytes());
        lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: act.as_ptr() as u64,
            oldact: 0,
            sigsetsize: 8,
        });

        // Read with act=null — should not change handler
        let mut oldact = [0u8; SIGACTION_SIZE];
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: 0, // null — read only
            oldact: oldact.as_mut_ptr() as u64,
            sigsetsize: 8,
        });
        assert_eq!(r, 0);
        let handler = u64::from_ne_bytes(oldact[0..8].try_into().unwrap());
        assert_eq!(handler, 0xBEEF);
    }

    #[test]
    fn test_sigaction_bad_sigsetsize() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let r = lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: 0,
            oldact: 0,
            sigsetsize: 4, // wrong — must be 8
        });
        assert_eq!(r, EINVAL);
    }

    #[test]
    fn test_sigaction_invalid_signum() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // signum 0 — invalid
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 0,
            act: 0,
            oldact: 0,
            sigsetsize: 8,
        });
        assert_eq!(r, EINVAL);

        // signum 65 — out of range
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 65,
            act: 0,
            oldact: 0,
            sigsetsize: 8,
        });
        assert_eq!(r, EINVAL);
    }

    #[test]
    fn test_sigprocmask_block() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let set: u64 = 1 << 9; // block signal 10 (SIGUSR1)
        let mut oldset: u64 = 0xFFFF;
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_BLOCK,
            set: &set as *const u64 as u64,
            oldset: &mut oldset as *mut u64 as u64,
            sigsetsize: 8,
        });
        assert_eq!(r, 0);
        assert_eq!(oldset, 0); // was empty before

        // Read back — should have bit 9 set
        let mut current: u64 = 0;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_BLOCK,
            set: 0,
            oldset: &mut current as *mut u64 as u64,
            sigsetsize: 8,
        });
        assert_eq!(current, 1 << 9);
    }

    #[test]
    fn test_sigprocmask_unblock() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Block signals 10 and 11
        let set: u64 = (1 << 9) | (1 << 10);
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: &set as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });

        // Unblock signal 10 only
        let unblock: u64 = 1 << 9;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_UNBLOCK,
            set: &unblock as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });

        // Should have only signal 11 blocked
        let mut current: u64 = 0;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_BLOCK,
            set: 0,
            oldset: &mut current as *mut u64 as u64,
            sigsetsize: 8,
        });
        assert_eq!(current, 1 << 10);
    }

    #[test]
    fn test_sigprocmask_setmask() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let mask: u64 = 0xDEADBEEF;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: &mask as *const u64 as u64,
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
        // SIGKILL (bit 8) and SIGSTOP (bit 18) cleared from 0xDEADBEEF
        let expected = 0xDEADBEEF & !(1u64 << 8 | 1u64 << 18);
        assert_eq!(current, expected);
    }

    #[test]
    fn test_sigprocmask_cannot_block_sigkill() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Try to block everything including SIGKILL and SIGSTOP
        let all: u64 = u64::MAX;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: &all as *const u64 as u64,
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
        // Bits for SIGKILL (8) and SIGSTOP (18) must be clear
        assert_eq!(current & (1 << 8), 0, "SIGKILL must not be blockable");
        assert_eq!(current & (1 << 18), 0, "SIGSTOP must not be blockable");
    }

    #[test]
    fn test_sigprocmask_bad_sigsetsize() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let r = lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_BLOCK,
            set: 0,
            oldset: 0,
            sigsetsize: 16,
        });
        assert_eq!(r, EINVAL);
    }

    #[test]
    fn test_sigprocmask_invalid_how() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        let set: u64 = 1;
        let r = lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: 99,
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

        // Set a handler and mask before forking
        let mut act = [0u8; SIGACTION_SIZE];
        act[0..8].copy_from_slice(&0xCAFEu64.to_ne_bytes());
        lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: act.as_ptr() as u64,
            oldact: 0,
            sigsetsize: 8,
        });

        let mask: u64 = 1 << 9;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: &mask as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });

        // Fork
        lx.dispatch_syscall(LinuxSyscall::Fork);

        // Child should have the same handler
        let child = lx.active_process();
        let mut oldact = [0u8; SIGACTION_SIZE];
        child.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: 0,
            oldact: oldact.as_mut_ptr() as u64,
            sigsetsize: 8,
        });
        let handler = u64::from_ne_bytes(oldact[0..8].try_into().unwrap());
        assert_eq!(handler, 0xCAFE);

        // Child should have the same mask
        let mut child_mask: u64 = 0;
        child.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_BLOCK,
            set: 0,
            oldset: &mut child_mask as *mut u64 as u64,
            sigsetsize: 8,
        });
        assert_eq!(child_mask, 1 << 9);
    }

    #[test]
    fn test_execve_resets_handlers_preserves_mask() {
        let mock = MockBackend::new();
        let mut lx = Linuxulator::new(mock);

        // Set handler and mask
        let mut act = [0u8; SIGACTION_SIZE];
        act[0..8].copy_from_slice(&0xBEEFu64.to_ne_bytes());
        lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: act.as_ptr() as u64,
            oldact: 0,
            sigsetsize: 8,
        });
        let mask: u64 = 1 << 9;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_SETMASK,
            set: &mask as *const u64 as u64,
            oldset: 0,
            sigsetsize: 8,
        });

        // Simulate execve state reset (can't do full execve on MockBackend)
        lx.reset_for_execve();

        // Handler should be SIG_DFL (0)
        let mut oldact = [0u8; SIGACTION_SIZE];
        lx.dispatch_syscall(LinuxSyscall::RtSigaction {
            signum: 10,
            act: 0,
            oldact: oldact.as_mut_ptr() as u64,
            sigsetsize: 8,
        });
        let handler = u64::from_ne_bytes(oldact[0..8].try_into().unwrap());
        assert_eq!(handler, SIG_DFL);

        // Mask should be preserved
        let mut current_mask: u64 = 0;
        lx.dispatch_syscall(LinuxSyscall::RtSigprocmask {
            how: SIG_BLOCK,
            set: 0,
            oldset: &mut current_mask as *mut u64 as u64,
            sigsetsize: 8,
        });
        assert_eq!(current_mask, 1 << 9);
    }
```

- [ ] **Step 3: Run all tests**

Run: `cargo test -p harmony-os 2>&1 | tail -15`
Expected: all pass including 14 new signal tests

- [ ] **Step 4: Run clippy and fmt**

Run: `cargo clippy -p harmony-os -- -D warnings 2>&1 | tail -10`
Run: `cargo fmt --all -- --check`

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "test(linuxulator): 14 signal state tests — sigaction, sigprocmask, fork/execve integration"
```

---

### Task 4: Final integration — full workspace, quality gates

- [ ] **Step 1: Run full workspace test suite**

Run: `cargo test --workspace 2>&1 | tail -10`

- [ ] **Step 2: Run clippy and fmt**

Run: `cargo clippy --workspace -- -D warnings 2>&1 | tail -10`
Run: `cargo fmt --all -- --check`

- [ ] **Step 3: Verify signal test count**

Run: `cargo test -p harmony-os 2>&1 | grep -E "test_sig|test result"`
Expected: 14 signal tests visible
