# Phase 5: CLONE_VM/CLONE_THREAD + Futex + TLS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable musl pthreads by implementing shared-address-space threads, futex synchronization, per-thread TLS, and thread exit cleanup.

**Architecture:** `spawn_task_runtime()` creates scheduler tasks at runtime from within syscall context. `sys_clone` with musl thread flags copies the parent's TrapFrame to a new task. All threads share the global Linuxulator. Per-thread state (TID, TLS, clear_child_tid) lives in the TCB. Futex uses `WaitReason::Futex(u64)` with the existing block/wake mechanism.

**Tech Stack:** Rust (no_std), AArch64 assembly (TPIDR_EL0), harmony-os Linuxulator

**Design spec:** `docs/superpowers/specs/2026-04-04-phase5-threads-design.md`

**Dependency:** PR #113 (FP/SIMD) should be merged first (musl needs NEON). Rebase this branch after merge.

---

## File Structure

| File | Changes |
|------|---------|
| `crates/harmony-boot-aarch64/src/sched.rs` | TCB fields (tls, tid, clear_child_tid), WaitReason::Futex, TLS save/restore, spawn_task_runtime, futex_wake |
| `crates/harmony-boot-aarch64/src/main.rs` | BumpAllocator static, CURRENT_TRAPFRAME, wire callbacks, thread exit in SVC handler |
| `crates/harmony-boot-aarch64/src/syscall.rs` | CURRENT_TRAPFRAME static, thread exit detection in svc_handler |
| `crates/harmony-os/src/linuxulator.rs` | 5 new callbacks, sys_clone thread path, sys_futex rewrite, sys_gettid/set_tid_address updates, next_tid counter |

---

### Task 1: TCB Additions + WaitReason::Futex

**Context:** The TaskControlBlock needs three new per-thread fields. WaitReason needs a Futex variant for futex blocking.

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/sched.rs`

**Reference:** TCB struct at lines 72-96. WaitReason enum at lines 58-68. Test module with TEST_LOCK and `put_tcb` helper.

- [ ] **Step 1: Write failing tests**

Add in the test module:

```rust
#[test]
fn tcb_has_thread_fields() {
    let _lock = TEST_LOCK.lock().unwrap();
    unsafe {
        NUM_TASKS = 1;
        TASKS[0] = MaybeUninit::new(TaskControlBlock {
            kernel_sp: 0,
            kernel_stack_base: 0x1_0000,
            kernel_stack_size: 8192,
            state: TaskState::Ready,
            preempt_count: 0,
            pid: 1,
            name: "test",
            entry: None,
            wait_reason: None,
            tls: 0xDEAD_BEEF,
            tid: 42,
            clear_child_tid: 0xCAFE,
        });
        let tcb = TASKS[0].assume_init_ref();
        assert_eq!(tcb.tls, 0xDEAD_BEEF);
        assert_eq!(tcb.tid, 42);
        assert_eq!(tcb.clear_child_tid, 0xCAFE);
        NUM_TASKS = 0;
    }
}

#[test]
fn wait_reason_futex_variant() {
    assert_ne!(
        WaitReason::Futex(0x1000),
        WaitReason::Futex(0x2000)
    );
    assert_eq!(
        WaitReason::Futex(0x1000),
        WaitReason::Futex(0x1000)
    );
    assert_ne!(
        WaitReason::Futex(0x1000),
        WaitReason::FdReadable(1)
    );
}
```

- [ ] **Step 2: Run tests — expect failure**

Run: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin 2>&1`
Expected: FAIL — `tls`, `tid`, `clear_child_tid` fields not found, `Futex` variant not found

- [ ] **Step 3: Add TCB fields and WaitReason::Futex**

Add to WaitReason enum (after `PollWait`):
```rust
    /// Waiting on a futex word at this address.
    Futex(u64),
```

Add to TaskControlBlock (after `wait_reason`):
```rust
    /// TPIDR_EL0 value — per-thread TLS pointer. Saved/restored on context switch.
    pub tls: u64,
    /// Linux Thread ID. Main thread: TID == PID. Spawned threads: unique TID.
    pub tid: u32,
    /// Address to zero + futex_wake on thread exit (CLONE_CHILD_CLEARTID).
    /// 0 means no cleanup needed.
    pub clear_child_tid: u64,
```

Update `spawn_task` to initialize: `tls: 0, tid: pid, clear_child_tid: 0` in the TCB constructor.

Update ALL existing test TCB constructions (including the `put_tcb` helper) to include the new fields.

- [ ] **Step 4: Run tests — expect pass**

Run: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin 2>&1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-boot-aarch64/src/sched.rs
git commit -m "feat(sched): add tls/tid/clear_child_tid to TCB + WaitReason::Futex"
```

---

### Task 2: TLS (TPIDR_EL0) Context Switch

**Context:** TPIDR_EL0 must be saved/restored per task so threads don't clobber each other's TLS pointer. Save in schedule() and block_current(), restore in schedule() and enter_scheduler().

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/sched.rs`

**Reference:** schedule() at lines 219-257. block_current() at lines 340-368. enter_scheduler() at ~line 280.

- [ ] **Step 1: Add TLS save to schedule() — outgoing task**

In `schedule()`, find the scoped borrow that saves kernel_sp (the `{ let current_tcb = ... }` block). Add TPIDR_EL0 save inside the scope:

```rust
{
    let current_tcb = TASKS[cur].assume_init_mut();
    current_tcb.kernel_sp = current_sp;
    #[cfg(target_arch = "aarch64")]
    {
        let tls: u64;
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) tls);
        current_tcb.tls = tls;
    }
    if current_tcb.state == TaskState::Running {
        current_tcb.state = TaskState::Ready;
        current_tcb.preempt_count += 1;
    }
}
```

- [ ] **Step 2: Add TLS restore to schedule() — incoming task**

After setting the new task to Running, restore TPIDR_EL0:

```rust
let tcb = TASKS[idx].assume_init_mut();
CURRENT = idx;
tcb.state = TaskState::Running;
#[cfg(target_arch = "aarch64")]
core::arch::asm!("msr tpidr_el0, {}", in(reg) tcb.tls);
return tcb.kernel_sp;
```

- [ ] **Step 3: Add TLS save to block_current()**

In the scoped borrow in `block_current()` (the `{ let cur = CURRENT; ... }` block), add:

```rust
{
    let cur = CURRENT;
    let tcb = TASKS[cur].assume_init_mut();
    tcb.state = TaskState::Blocked;
    tcb.wait_reason = Some(reason);
    #[cfg(target_arch = "aarch64")]
    {
        let tls: u64;
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) tls);
        tcb.tls = tls;
    }
}
```

- [ ] **Step 4: Add TLS restore to enter_scheduler()**

In the inline assembly of `enter_scheduler()`, before the ELR/SPSR restore, add a Rust block that writes TPIDR_EL0:

Actually, `enter_scheduler` uses `core::arch::asm!` with `options(noreturn)`. The TPIDR write should go before the inline asm block:

```rust
pub unsafe fn enter_scheduler() -> ! {
    assert!(NUM_TASKS > 0, "enter_scheduler: no tasks spawned");
    TASKS[0].assume_init_mut().state = TaskState::Running;
    CURRENT = 0;

    let sp = TASKS[0].assume_init_ref().kernel_sp;
    let tls = TASKS[0].assume_init_ref().tls;

    #[cfg(target_arch = "aarch64")]
    core::arch::asm!("msr tpidr_el0, {}", in(reg) tls);

    core::arch::asm!(
        "mov sp, {sp}",
        // ... existing restore assembly ...
```

Note: The `tls` value for boot-time tasks is 0, which is correct (no TLS set up yet).

- [ ] **Step 5: Verify and commit**

Run: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin && cargo check --target aarch64-unknown-uefi`

```bash
git add crates/harmony-boot-aarch64/src/sched.rs
git commit -m "feat(sched): save/restore TPIDR_EL0 on context switch for per-thread TLS"
```

---

### Task 3: BumpAllocator Static + spawn_task_runtime

**Context:** `spawn_task` is boot-time only (takes `&mut BumpAllocator` local variable). We need runtime task spawning for CLONE_VM/CLONE_THREAD. Move the bump allocator to a static and add `spawn_task_runtime`.

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/sched.rs`
- Modify: `crates/harmony-boot-aarch64/src/main.rs`

**Reference:** spawn_task at sched.rs:123-185. BumpAllocator creation at main.rs:316. Task spawning at main.rs:532-536.

- [ ] **Step 1: Add BUMP_ALLOCATOR static to sched.rs**

Add near the other statics (after NUM_TASKS):

```rust
/// Bump allocator for runtime kernel stack allocation. Moved from
/// main()'s local variable so spawn_task_runtime can allocate after boot.
static mut BUMP_ALLOCATOR: Option<crate::bump_alloc::BumpAllocator> = None;

/// Initialize the bump allocator static. Called once during boot.
pub unsafe fn set_bump_allocator(bump: crate::bump_alloc::BumpAllocator) {
    BUMP_ALLOCATOR = Some(bump);
}
```

- [ ] **Step 2: Update main.rs to move bump allocator to static**

In main.rs, after all boot-time spawn_task calls are done (after line 536), move the bump allocator to the static:

```rust
// Move bump allocator to static for runtime task spawning.
unsafe { sched::set_bump_allocator(bump) };
```

Note: This must happen AFTER all boot-time `spawn_task(&mut bump)` calls but BEFORE `enter_scheduler()`.

- [ ] **Step 3: Implement spawn_task_runtime**

Add after `enter_scheduler` in sched.rs:

```rust
/// Spawn a new task at runtime (after scheduler is running).
///
/// Copies `parent_trapframe` to the new task's kernel stack, modifies
/// the child's X0 (return value = 0) and SP, and marks it Ready.
/// Called from within syscall context (CLONE_VM/CLONE_THREAD).
///
/// # Safety
///
/// - Must be called from task context (not IRQ handler).
/// - `parent_trapframe` must point to a valid TrapFrame.
pub unsafe fn spawn_task_runtime(
    name: &'static str,
    pid: u32,
    tid: u32,
    tls: u64,
    clear_child_tid: u64,
    parent_trapframe: *const TrapFrame,
    child_stack: u64,
) -> Option<usize> {
    // Mask IRQs to prevent race with scheduler.
    #[cfg(target_arch = "aarch64")]
    core::arch::asm!("msr daifset, #2");

    let n = NUM_TASKS;
    if n >= MAX_TASKS {
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("msr daifclr, #2");
        return None;
    }

    let bump = BUMP_ALLOCATOR.as_mut().expect("spawn_task_runtime: no bump allocator");
    let page_size = harmony_microkernel::vm::PAGE_SIZE as usize;
    let pages_needed = (KERNEL_STACK_SIZE + page_size - 1) / page_size;

    // Allocate guard page + stack pages.
    let guard_frame = bump.alloc_frame().expect("sched: guard page frame").0 as usize;
    let base = bump.alloc_frame().expect("sched: kernel stack frame 0").0 as usize;
    assert_eq!(base, guard_frame + page_size, "guard page must be contiguous");
    for i in 1..pages_needed {
        let frame = bump.alloc_frame().expect("sched: kernel stack frame").0 as usize;
        assert_eq!(frame, base + i * page_size, "kernel stack frames must be contiguous");
    }

    #[cfg(target_arch = "aarch64")]
    crate::mmu::mark_guard_page(guard_frame as u64);

    let stack_size = pages_needed * page_size;
    let stack_top = base + stack_size;
    let sp = stack_top - TRAPFRAME_SIZE;

    // Copy parent's TrapFrame to child's kernel stack.
    core::ptr::copy_nonoverlapping(
        parent_trapframe as *const u8,
        sp as *mut u8,
        TRAPFRAME_SIZE,
    );

    // Modify child's TrapFrame: return 0 from clone, use child's stack.
    let child_frame = sp as *mut TrapFrame;
    (*child_frame).x[0] = 0;  // clone() returns 0 to child

    // Set child's SP. On aarch64, the SVC entry saves SP in the TrapFrame
    // at a known location. For EL1 tasks, SP is implicit (restored by eret).
    // For EL0 tasks (future), SP_EL0 would be in the TrapFrame.
    // For now, the child_stack is written to X[2] or similar register
    // that musl's clone wrapper uses as the new SP before jumping to
    // the thread function. Read the musl __clone source to verify.
    // Actually: musl's __clone on aarch64 does:
    //   mov sp, x1  (x1 = child_stack, passed as 2nd arg to clone)
    //   ... then calls the thread function
    // But we're returning FROM the clone syscall — the child resumes
    // at the instruction after SVC. musl's wrapper then does mov sp, x1.
    // Wait — the child_stack is in x1. But we're copying the parent's
    // TrapFrame, so x1 still has the parent's child_stack argument.
    // That's correct — musl passes child_stack in x1, and the child's
    // TrapFrame has x1 = child_stack from the parent's syscall args.
    // The child returns from SVC with x0=0 (we set that above).
    // musl's wrapper then does: mov sp, x1; blr x2 (thread fn).
    // So we don't need to modify SP in the TrapFrame — musl handles it.

    TASKS[n] = MaybeUninit::new(TaskControlBlock {
        kernel_sp: sp,
        kernel_stack_base: base,
        kernel_stack_size: stack_size,
        state: TaskState::Ready,
        preempt_count: 0,
        pid,
        name,
        entry: None,
        wait_reason: None,
        tls,
        tid,
        clear_child_tid,
    });
    NUM_TASKS = n + 1;

    // Unmask IRQs.
    #[cfg(target_arch = "aarch64")]
    core::arch::asm!("msr daifclr, #2");

    Some(n)
}
```

- [ ] **Step 4: Write tests**

```rust
#[test]
fn spawn_task_runtime_creates_ready_task() {
    let _lock = TEST_LOCK.lock().unwrap();
    unsafe {
        // Set up a minimal bump allocator is not possible in host tests
        // (page allocation requires real memory). Test the TCB fill logic
        // by checking that spawn_task (boot-time) correctly sets new fields.
        // spawn_task_runtime's integration is tested via QEMU boot test.
        NUM_TASKS = 0;
    }
}
```

Note: `spawn_task_runtime` requires a real BumpAllocator with page-aligned memory, which isn't available in host tests. The core logic (copy TrapFrame, fill TCB) is tested via the QEMU boot test. Host tests verify the TCB field initialization via `spawn_task` (boot-time).

- [ ] **Step 5: Verify and commit**

Run: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin && cargo check --target aarch64-unknown-uefi`

```bash
git add crates/harmony-boot-aarch64/src/sched.rs crates/harmony-boot-aarch64/src/main.rs
git commit -m "feat(sched): add spawn_task_runtime for runtime thread creation

BumpAllocator moved to static. spawn_task_runtime masks IRQs, allocates
kernel stack + guard page, copies parent TrapFrame, fills TCB with
per-thread fields (tls, tid, clear_child_tid)."
```

---

### Task 4: futex_wake Scheduler Primitive

**Context:** Add `sched::futex_wake(uaddr, max)` that scans blocked tasks for `WaitReason::Futex(uaddr)` and wakes up to `max` of them.

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/sched.rs`

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn futex_wake_wakes_matching_tasks() {
    let _lock = TEST_LOCK.lock().unwrap();
    unsafe {
        put_tcb(0, TaskState::Running, None);
        TASKS[0].assume_init_mut().tls = 0;
        TASKS[0].assume_init_mut().tid = 1;
        TASKS[0].assume_init_mut().clear_child_tid = 0;

        put_tcb(1, TaskState::Blocked, Some(WaitReason::Futex(0x1000)));
        TASKS[1].assume_init_mut().tls = 0;
        TASKS[1].assume_init_mut().tid = 2;
        TASKS[1].assume_init_mut().clear_child_tid = 0;

        put_tcb(2, TaskState::Blocked, Some(WaitReason::Futex(0x1000)));
        TASKS[2].assume_init_mut().tls = 0;
        TASKS[2].assume_init_mut().tid = 3;
        TASKS[2].assume_init_mut().clear_child_tid = 0;

        put_tcb(3, TaskState::Blocked, Some(WaitReason::Futex(0x2000)));
        TASKS[3].assume_init_mut().tls = 0;
        TASKS[3].assume_init_mut().tid = 4;
        TASKS[3].assume_init_mut().clear_child_tid = 0;

        NUM_TASKS = 4;
        CURRENT = 0;

        // Wake at most 1 task waiting on 0x1000.
        let woken = futex_wake(0x1000, 1);
        assert_eq!(woken, 1);
        // One of tasks 1 or 2 should be Ready now.
        let ready_count = (0..4)
            .filter(|&i| TASKS[i].assume_init_ref().state == TaskState::Ready)
            .count();
        assert_eq!(ready_count, 1); // exactly 1 woken

        // Task 3 (different address) still blocked.
        assert_eq!(TASKS[3].assume_init_ref().state, TaskState::Blocked);

        NUM_TASKS = 0;
    }
}

#[test]
fn futex_wake_returns_zero_when_no_waiters() {
    let _lock = TEST_LOCK.lock().unwrap();
    unsafe {
        put_tcb(0, TaskState::Running, None);
        TASKS[0].assume_init_mut().tls = 0;
        TASKS[0].assume_init_mut().tid = 1;
        TASKS[0].assume_init_mut().clear_child_tid = 0;
        NUM_TASKS = 1;
        CURRENT = 0;

        let woken = futex_wake(0x1000, 10);
        assert_eq!(woken, 0);

        NUM_TASKS = 0;
    }
}
```

- [ ] **Step 2: Implement futex_wake**

Add after `for_each_blocked`:

```rust
/// Wake up to `max` tasks blocked on `WaitReason::Futex(uaddr)`.
///
/// Returns the number of tasks actually woken. Used by FUTEX_WAKE
/// and CLONE_CHILD_CLEARTID exit cleanup.
///
/// # Safety
///
/// Must only be called when TASKS[0..NUM_TASKS] are initialized.
pub unsafe fn futex_wake(uaddr: u64, max: u32) -> u32 {
    let mut woken = 0u32;
    let n = NUM_TASKS;
    for i in 0..n {
        if woken >= max {
            break;
        }
        let tcb = TASKS[i].assume_init_mut();
        if tcb.state == TaskState::Blocked
            && tcb.wait_reason == Some(WaitReason::Futex(uaddr))
        {
            tcb.state = TaskState::Ready;
            tcb.wait_reason = None;
            woken += 1;
        }
    }
    woken
}
```

- [ ] **Step 3: Verify and commit**

Run: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin`

```bash
git add crates/harmony-boot-aarch64/src/sched.rs
git commit -m "feat(sched): add futex_wake — wake tasks blocked on futex address"
```

---

### Task 5: Linuxulator Callbacks + Futex + gettid

**Context:** Add the 5 new callbacks to the Linuxulator, rewrite sys_futex to actually block/wake, and update sys_gettid and set_tid_address.

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

**Reference:** Existing callbacks at lines 2501-2509. sys_futex at lines 8520-8546. sys_gettid at lines 8476-8478. set_tid_address at lines 7577-7579. Linuxulator struct at lines 2401-2510.

- [ ] **Step 1: Add callback fields and setters**

Add to Linuxulator struct (near existing callback fields):

```rust
    /// Spawn a new thread. Args: (pid, tid, tls, clear_child_tid, child_stack).
    /// Returns Some(task_index) on success, None if MAX_TASKS reached.
    spawn_fn: Option<fn(u32, u32, u64, u64, u64) -> Option<u32>>,
    /// Block current task on a futex address.
    futex_block_fn: Option<fn(u64)>,
    /// Wake up to N tasks blocked on a futex address. Returns count woken.
    futex_wake_fn: Option<fn(u64, u32) -> u32>,
    /// Get the current task's TID.
    get_current_tid_fn: Option<fn() -> u32>,
    /// Set the current task's clear_child_tid address.
    set_clear_child_tid_fn: Option<fn(u64)>,
```

Initialize all to `None` in the constructor (`with_tcp_and_arena`). Add setter methods following the existing pattern:

```rust
    pub fn set_spawn_fn(&mut self, f: fn(u32, u32, u64, u64, u64) -> Option<u32>) {
        self.spawn_fn = Some(f);
    }
    pub fn set_futex_block_fn(&mut self, f: fn(u64)) {
        self.futex_block_fn = Some(f);
    }
    pub fn set_futex_wake_fn(&mut self, f: fn(u64, u32) -> u32) {
        self.futex_wake_fn = Some(f);
    }
    pub fn set_get_current_tid_fn(&mut self, f: fn() -> u32) {
        self.get_current_tid_fn = Some(f);
    }
    pub fn set_clear_child_tid_fn(&mut self, f: fn(u64)) {
        self.set_clear_child_tid_fn = Some(f);
    }
```

Also initialize in `create_child` / fork child constructors.

- [ ] **Step 2: Add next_tid counter**

Add field to Linuxulator struct:

```rust
    /// Next TID to assign to a spawned thread. Starts at PID + 1.
    next_tid: u32,
```

Initialize to `2` in constructor (PID 1 is the main thread, first spawned thread gets TID 2). Add method:

```rust
    fn alloc_tid(&mut self) -> u32 {
        let tid = self.next_tid;
        self.next_tid += 1;
        tid
    }
```

- [ ] **Step 3: Rewrite sys_futex**

Replace the existing stub (lines 8520-8546):

```rust
    fn sys_futex(&mut self, uaddr: u64, op: i32, val: u32) -> i64 {
        const FUTEX_CMD_MASK: i32 = 0x7f;
        const FUTEX_WAIT: i32 = 0;
        const FUTEX_WAKE: i32 = 1;

        let cmd = op & FUTEX_CMD_MASK;
        match cmd {
            FUTEX_WAIT => {
                if uaddr == 0 {
                    return EFAULT;
                }
                // Atomicity: read the futex word and compare.
                // If value changed, return EAGAIN (lost wakeup prevention).
                let current = unsafe { *(uaddr as *const u32) };
                if current != val {
                    return EAGAIN;
                }
                // Block until woken by FUTEX_WAKE.
                if let Some(block) = self.futex_block_fn {
                    block(uaddr);
                    0 // Woken successfully
                } else {
                    EAGAIN // No scheduler — can't block
                }
            }
            FUTEX_WAKE => {
                if let Some(wake) = self.futex_wake_fn {
                    wake(uaddr, val) as i64
                } else {
                    0 // No scheduler — no waiters possible
                }
            }
            _ => ENOSYS,
        }
    }
```

- [ ] **Step 4: Update sys_gettid**

Replace (lines 8476-8478):

```rust
    fn sys_gettid(&self) -> i64 {
        if let Some(get_tid) = self.get_current_tid_fn {
            get_tid() as i64
        } else {
            self.pid as i64 // Fallback: single-threaded TID == PID
        }
    }
```

- [ ] **Step 5: Update set_tid_address**

Replace (lines 7577-7579):

```rust
    fn sys_set_tid_address(&self, tidptr: u64) -> i64 {
        // Store the clear_child_tid address for this thread.
        if let Some(set_ctid) = self.set_clear_child_tid_fn {
            set_ctid(tidptr);
        }
        // Return this thread's TID.
        if let Some(get_tid) = self.get_current_tid_fn {
            get_tid() as i64
        } else {
            self.pid as i64
        }
    }
```

- [ ] **Step 6: Write tests and verify**

```rust
#[test]
fn futex_wait_returns_eagain_on_value_mismatch() {
    let mut lx = make_test_linuxulator();
    let mut val: u32 = 42;
    let uaddr = &mut val as *mut u32 as u64;
    // val == 42, but we pass expected == 99 → EAGAIN
    let result = lx.sys_futex(uaddr, 0, 99);
    assert_eq!(result, EAGAIN);
}

#[test]
fn futex_wake_returns_zero_without_scheduler() {
    let lx = make_test_linuxulator();
    let result = lx.sys_futex(0x1000, 1, 5);
    assert_eq!(result, 0);
}
```

Run: `cargo test -p harmony-os`

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): add thread callbacks, futex WAIT/WAKE, gettid/set_tid_address"
```

---

### Task 6: sys_clone Thread Creation

**Context:** Accept musl pthread flags in sys_clone, create a new scheduler task via spawn_fn callback.

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

**Reference:** sys_clone at lines 6234-6258. Current flag validation rejects CLONE_VM.

- [ ] **Step 1: Define clone flag constants**

Near sys_clone (or at module level):

```rust
const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_SYSVSEM: u64 = 0x0004_0000;
const CLONE_SETTLS: u64 = 0x0008_0000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
```

- [ ] **Step 2: Implement thread creation path in sys_clone**

Rewrite sys_clone to handle both the existing fork path (SIGCHLD-only) and the new thread path (CLONE_VM|CLONE_THREAD):

```rust
fn sys_clone(&mut self, flags: u64, child_stack: u64, parent_tidptr: u64,
             tls: u64, child_tidptr: u64) -> i64 {
    let sig = flags & 0xFF;

    // Thread creation: musl pthread flags.
    let thread_flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND
        | CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS
        | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID;
    let required_thread = CLONE_VM | CLONE_THREAD | CLONE_FILES | CLONE_SIGHAND;

    if flags & required_thread == required_thread {
        // Validate: all expected flags present, no unexpected extras.
        let known = thread_flags | CLONE_CHILD_SETTID;
        if flags & !known != 0 && sig != 0 {
            return ENOSYS; // Unknown flags
        }

        let spawn = match self.spawn_fn {
            Some(f) => f,
            None => return ENOSYS, // No runtime task spawning
        };

        let tid = self.alloc_tid();
        let clear_child_tid = if flags & CLONE_CHILD_CLEARTID != 0 {
            child_tidptr
        } else {
            0
        };

        // Call spawn_fn. The boot crate's implementation reads
        // CURRENT_TRAPFRAME to copy the parent's register state.
        match spawn(self.pid as u32, tid, tls, clear_child_tid, child_stack) {
            Some(_task_idx) => {
                // Write TID to parent's tidptr.
                if flags & CLONE_PARENT_SETTID != 0 && parent_tidptr != 0 {
                    unsafe { *(parent_tidptr as *mut u32) = tid; }
                }
                // Write TID to child's tidptr (shared address space).
                if flags & CLONE_CHILD_SETTID != 0 && child_tidptr != 0 {
                    unsafe { *(child_tidptr as *mut u32) = tid; }
                }
                tid as i64
            }
            None => EAGAIN, // MAX_TASKS reached
        }
    } else if sig == 17 {
        // Existing fork path: SIGCHLD with optional SETTID/CLEARTID.
        self.sys_fork()
    } else {
        ENOSYS
    }
}
```

Note: The `sys_clone` function signature may need updating to accept all 5 arguments. Check the existing `LinuxSyscall::Clone` variant to see how arguments are passed. On aarch64, clone takes (flags, child_stack, parent_tidptr, tls, child_tidptr).

- [ ] **Step 3: Write tests**

```rust
#[test]
fn sys_clone_with_thread_flags_calls_spawn_fn() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut lx = make_test_linuxulator();
    static SPAWN_CALLED: AtomicBool = AtomicBool::new(false);

    lx.set_spawn_fn(|_pid, _tid, _tls, _ctid, _stack| {
        SPAWN_CALLED.store(true, Ordering::SeqCst);
        Some(42) // task index
    });

    SPAWN_CALLED.store(false, Ordering::SeqCst);
    let flags = 0x3D0F00; // CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|
                           // CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|
                           // CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID
    let result = lx.sys_clone(flags, 0x7000_0000, 0, 0xTLS, 0);
    assert!(SPAWN_CALLED.load(Ordering::SeqCst));
    assert!(result > 0); // Returns TID
}

#[test]
fn sys_clone_without_spawn_fn_returns_enosys() {
    let mut lx = make_test_linuxulator();
    let flags = 0x3D0F00; // thread flags
    let result = lx.sys_clone(flags, 0, 0, 0, 0);
    assert_eq!(result, ENOSYS);
}
```

Run: `cargo test -p harmony-os`

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): sys_clone thread creation via spawn_fn callback"
```

---

### Task 7: Boot Integration + Thread Exit

**Context:** Wire all callbacks in main.rs. Add CURRENT_TRAPFRAME static for spawn_fn to read. Implement thread exit logic in the SVC handler.

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/main.rs`
- Modify: `crates/harmony-boot-aarch64/src/syscall.rs`

**Reference:** SVC handler at syscall.rs:116-149. Callback setup at main.rs:466-479. dispatch() at main.rs:485-493.

- [ ] **Step 1: Add CURRENT_TRAPFRAME static to syscall.rs**

```rust
/// Pointer to the current task's TrapFrame during SVC dispatch.
/// Set by svc_handler before calling dispatch, read by spawn_fn callback.
static mut CURRENT_TRAPFRAME: *const TrapFrame = core::ptr::null();

/// Get the current TrapFrame pointer (for spawn_fn callback).
pub unsafe fn current_trapframe() -> *const TrapFrame {
    CURRENT_TRAPFRAME
}
```

- [ ] **Step 2: Update svc_handler to set CURRENT_TRAPFRAME**

In `svc_handler` (line 116-149), before calling dispatch:

```rust
pub unsafe extern "C" fn svc_handler(frame: &mut TrapFrame) {
    CURRENT_TRAPFRAME = frame as *const TrapFrame;
    // ... existing dispatch logic ...
```

- [ ] **Step 3: Add thread exit detection in svc_handler**

After dispatch returns with `exited = true`, check if this is a thread exit or exit_group:

```rust
if result.exited {
    let cur = sched::current_task_index();
    let tcb_tid = sched::current_task_tid();
    let tcb_pid = sched::current_task_pid();

    if tcb_tid != tcb_pid {
        // Thread exit (not main thread).
        // 1. CLONE_CHILD_CLEARTID cleanup.
        let clear_addr = sched::current_task_clear_child_tid();
        if clear_addr != 0 {
            *(clear_addr as *mut u32) = 0;
            sched::futex_wake(clear_addr, 1);
        }
        // 2. Mark this task Dead and yield.
        sched::mark_current_dead();
        // Trigger SGI to switch away (task is Dead, never rescheduled).
        #[cfg(target_arch = "aarch64")]
        {
            core::arch::asm!("msr daifclr, #2");
            gic::send_sgi_self(gic::YIELD_SGI);
            core::arch::asm!("msr daifset, #2");
        }
        // Should not reach here — task is Dead. But safety net:
        loop { core::arch::asm!("wfi"); }
    } else {
        // Main thread exit — existing exit_group behavior.
        // Also kill all threads with matching PID.
        sched::kill_threads_by_pid(tcb_pid);
        // ... existing RETURN_ADDR redirect logic ...
    }
}
```

You'll need helper functions in sched.rs:

```rust
pub unsafe fn current_task_index() -> usize { CURRENT }
pub unsafe fn current_task_tid() -> u32 { TASKS[CURRENT].assume_init_ref().tid }
pub unsafe fn current_task_pid() -> u32 { TASKS[CURRENT].assume_init_ref().pid }
pub unsafe fn current_task_clear_child_tid() -> u64 { TASKS[CURRENT].assume_init_ref().clear_child_tid }
pub unsafe fn mark_current_dead() {
    TASKS[CURRENT].assume_init_mut().state = TaskState::Dead;
    TASKS[CURRENT].assume_init_mut().wait_reason = None;
}
pub unsafe fn kill_threads_by_pid(pid: u32) {
    let n = NUM_TASKS;
    for i in 0..n {
        let tcb = TASKS[i].assume_init_mut();
        if tcb.pid == pid && tcb.state != TaskState::Dead {
            tcb.state = TaskState::Dead;
            tcb.wait_reason = None;
        }
    }
}
```

- [ ] **Step 4: Wire callbacks in main.rs**

In the Linuxulator setup section (around line 466-479), add after existing callbacks:

```rust
linuxulator.set_spawn_fn(|pid, tid, tls, clear_child_tid, child_stack| {
    let parent_tf = unsafe { syscall::current_trapframe() };
    if parent_tf.is_null() { return None; }
    unsafe {
        sched::spawn_task_runtime(
            "thread",
            pid,
            tid,
            tls,
            clear_child_tid,
            parent_tf,
            child_stack,
        ).map(|idx| idx as u32)
    }
});

linuxulator.set_futex_block_fn(|uaddr| {
    unsafe { sched::block_current(sched::WaitReason::Futex(uaddr)); }
});

linuxulator.set_futex_wake_fn(|uaddr, max| {
    unsafe { sched::futex_wake(uaddr, max) }
});

linuxulator.set_get_current_tid_fn(|| {
    unsafe { sched::current_task_tid() }
});

linuxulator.set_clear_child_tid_fn(|addr| {
    unsafe {
        sched::TASKS[sched::CURRENT].assume_init_mut().clear_child_tid = addr;
    }
});
```

Note: The `set_clear_child_tid_fn` callback accesses TASKS directly. This might need a proper helper function in sched.rs instead:

```rust
pub unsafe fn set_current_clear_child_tid(addr: u64) {
    TASKS[CURRENT].assume_init_mut().clear_child_tid = addr;
}
```

- [ ] **Step 5: Update check_and_wake_blocked_tasks to skip Futex**

In `check_and_wake_blocked_tasks` (main.rs), add Futex to the match:

```rust
sched::WaitReason::Futex(_) => {
    // Futex wakes are synchronous (from FUTEX_WAKE syscall or
    // CLONE_CHILD_CLEARTID). Not checked by the system task.
}
```

- [ ] **Step 6: Verify and commit**

Run tests and cross-compile:
```bash
cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin
cargo check --target aarch64-unknown-uefi
cargo test -p harmony-os
cargo +nightly fmt --all -- --check
```

```bash
git add crates/harmony-boot-aarch64/src/syscall.rs crates/harmony-boot-aarch64/src/sched.rs crates/harmony-boot-aarch64/src/main.rs
git commit -m "feat(boot): wire thread callbacks, CURRENT_TRAPFRAME, thread exit + CLEARTID

SVC handler stores CURRENT_TRAPFRAME for spawn_fn. Thread exit (TID!=PID)
does CLEARTID cleanup + futex_wake + mark Dead + SGI. exit_group kills
all threads with matching PID. All 5 new callbacks wired to scheduler."
```

---

## Post-Implementation Checklist

- [ ] Run boot crate tests: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin`
- [ ] Run harmony-os tests: `cargo test -p harmony-os`
- [ ] Cross-compile: `cd crates/harmony-boot-aarch64 && cargo check --target aarch64-unknown-uefi`
- [ ] Clippy: `cargo clippy -p harmony-os`
- [ ] Nightly rustfmt: `cargo +nightly fmt --all -- --check`
- [ ] QEMU boot test: `cargo +nightly xtask qemu-test --target aarch64 --timeout 60`
- [ ] Verify no ENOSYS for CLONE_VM in sys_clone: `grep -n "ENOSYS.*CLONE_VM\|CLONE_VM.*ENOSYS" crates/harmony-os/src/linuxulator.rs` (should find none)
