# x86_64 Kernel Stack Switch Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Switch the x86_64 kernel to a 128KB heap-allocated stack so PQ keygen (ML-KEM-768 + ML-DSA-65) can run without overflowing the bootloader's ~16KB stack.

**Architecture:** Split `kernel_main` into early-boot (serial, PIT, phys_offset, heap, stack allocation) and `kernel_continue` (everything from RDRAND onward). An inline assembly trampoline switches RSP between them. `BootState` carries early-boot values across the switch via a heap-allocated `Box`.

**Tech Stack:** Rust (no_std, x86_64-unknown-none), inline asm (`core::arch::asm!`), `bootloader_api` v0.11, `linked_list_allocator` v0.10

**Spec:** `docs/plans/2026-03-19-x86-kernel-stack-design.md`

---

### Task 1: Add `BootState` struct and `switch_to_stack` trampoline

**Files:**
- Modify: `crates/harmony-boot/src/main.rs`

- [ ] **Step 1: Add the `BootState` struct and stack constant**

Add above `kernel_main`, after the `ALLOCATOR` static:

```rust
/// Size of the heap-allocated kernel stack in bytes.
/// 128KB provides ~5x headroom for PQ lattice operations (ML-KEM + ML-DSA ~25KB).
const KERNEL_STACK_SIZE: usize = 128 * 1024;

/// State from early boot that must survive the stack switch.
/// Heap-allocated via `Box` so the pointer remains valid after RSP changes.
struct BootState {
    boot_info: &'static mut BootInfo,
    phys_offset: u64,
    pit: pit::PitTimer,
}
```

- [ ] **Step 2: Add the assembly trampoline**

Add below `BootState`:

```rust
/// Switch RSP to `new_stack_top` and call `continuation(state)`.
///
/// # Safety
/// - `new_stack_top` must be a valid, 16-byte-aligned, writable address
///   with sufficient space below it for the continuation's stack usage.
/// - `continuation` must be `extern "C"` and never return.
/// - `state` is passed as `rdi` (SysV ABI first argument).
unsafe fn switch_to_stack(
    state: *mut BootState,
    new_stack_top: usize,
    continuation: unsafe extern "C" fn(*mut BootState) -> !,
) -> ! {
    core::arch::asm!(
        "mov rsp, {stack}",
        "call {cont}",
        "ud2",
        stack = in(reg) new_stack_top,
        cont = in(reg) continuation,
        in("rdi") state,
        options(noreturn),
    );
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cd crates/harmony-boot && cargo check --target x86_64-unknown-none`
Expected: Compiles (warnings about unused items are fine).

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-boot/src/main.rs
git commit -m "feat(boot): add BootState struct and switch_to_stack trampoline"
```

---

### Task 2: Split `kernel_main` — early boot stays, rest moves to `kernel_continue`

**Files:**
- Modify: `crates/harmony-boot/src/main.rs`

This is the main refactor. `kernel_main` keeps serial, PIT, phys_offset, heap (in that order — matching the current code), then allocates the stack, packs `BootState`, and calls the trampoline. `kernel_continue` receives `BootState` and does everything from RDRAND onward, including ring2/ring3 blocks and the event loop.

**Important:** `kernel_continue` is `-> !`. Multiple paths provide the divergence:
- The `ring3` feature block has a `noreturn` asm jump (existing behavior — unchanged).
- The `qemu-test` feature calls `qemu_debug_exit()` which terminates QEMU.
- The default event loop is `loop { ... }`.
All three paths are preserved as-is when moved into `kernel_continue`.

- [ ] **Step 1: Create `kernel_continue` function**

Add a new `extern "C"` function after `kernel_main`. This function takes ownership of `BootState` and runs the rest of boot. Copy everything from the RDRAND check (line 273) through the end of `kernel_main` (the event loop, ring2/ring3 blocks, qemu-test exit, everything) into this new function.

Key changes in the moved code:
- Reconstruct `serial` via `serial_writer()` (stateless — just port I/O).
- Unbox `BootState` to get `boot_info`, `phys_offset`, `pit`. (`heap_size` is not carried — only used for the `[HEAP]` log in `kernel_main`.)
- Remove the `cfg(not(feature = "qemu-test"))` gate on PQ keygen — the new stack is large enough.
- `hex_buf` is a new local (it was on the old stack).

Function signature:

```rust
/// Kernel continuation — runs on the 128KB heap-allocated stack.
/// Receives early-boot state via a heap-allocated `BootState`.
unsafe extern "C" fn kernel_continue(state: *mut BootState) -> ! {
    let state = *Box::from_raw(state);
    let boot_info = state.boot_info;
    let phys_offset = state.phys_offset;
    let mut pit = state.pit;
    let mut serial = serial_writer();

    let _ = writeln!(serial, "[STACK] switched to {}KB heap stack", KERNEL_STACK_SIZE / 1024);

    // ... rest of boot from RDRAND onward ...
}
```

- [ ] **Step 2: Rewrite `kernel_main` to stop after stack switch**

`kernel_main` now:
1. serial_init, serial_writer, log BOOT
2. PIT init, log PIT
3. phys_offset
4. heap init (unchanged)
5. Allocate stack, compute stack_top, forget the Vec
6. Pack BootState into Box, leak to raw pointer
7. Call `switch_to_stack`

```rust
fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    // 1. Serial init
    serial_init();
    let mut serial = serial_writer();
    serial.log("BOOT", "Harmony unikernel v0.1.0");

    // 2. PIT timer
    let pit = pit::PitTimer::init();
    serial.log("PIT", "timer initialized");

    // 3. Physical memory offset
    let phys_offset = boot_info
        .physical_memory_offset
        .into_option()
        .expect("physical_memory_offset not provided by bootloader");

    // 4. Heap init — existing scan + init logic (declares heap_size, logs [HEAP])
    // ... existing heap init code unchanged ...

    // 5. Allocate kernel stack
    let stack_vec = alloc::vec![0u8; KERNEL_STACK_SIZE];
    let stack_top = (stack_vec.as_ptr() as usize + KERNEL_STACK_SIZE) & !0xF;
    core::mem::forget(stack_vec); // kernel owns this stack permanently
    let _ = writeln!(serial, "[STACK] allocated {}KB at {:#x}", KERNEL_STACK_SIZE / 1024, stack_top);

    // 6. Pack early-boot state (heap_size not carried — only used for [HEAP] log above)
    let state = Box::into_raw(Box::new(BootState {
        boot_info,
        phys_offset,
        pit,
    }));

    // 7. Switch to heap stack and continue boot
    unsafe { switch_to_stack(state, stack_top, kernel_continue) }
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cd crates/harmony-boot && cargo check --target x86_64-unknown-none`
Expected: Compiles. May have warnings about moved code — fix any borrow issues.

- [ ] **Step 4: Run workspace tests**

Run: `cargo test --workspace`
Expected: All tests pass (boot crate is no_std, not tested by workspace tests — this verifies nothing else broke).

- [ ] **Step 5: Run fmt and clippy**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings`
Expected: Clean. If fmt fails, run `cargo fmt --all` first.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-boot/src/main.rs
git commit -m "feat(boot): split kernel_main — switch to 128KB heap stack before RDRAND

Early boot (serial, PIT, heap) runs on the bootloader's ~16KB stack.
Everything from RDRAND onward (identity, PQ keygen, VirtIO, netstack,
event loop) runs on a 128KB heap-allocated stack.

Removes cfg(not(feature = \"qemu-test\")) gate on PQ keygen — the
new stack is large enough for ML-KEM/ML-DSA lattice operations."
```

---

### Task 3: Verify QEMU boot passes locally (if nix available)

**Files:**
- No file changes — verification only.

- [ ] **Step 1: Build x86_64 boot image**

Run (inside `nix develop`):
```bash
cargo xtask qemu-test --target x86_64
```

Expected: All 4 milestones pass. Serial output should show:
```
[BOOT] Harmony unikernel v0.1.0
[PIT] timer initialized
[HEAP] 4194304
[STACK] allocated 128KB at 0x...
[ENTROPY] RDRAND available
[IDENTITY] <hex>
[PQ_IDENTITY] <hex>
...
[READY] entering event loop
```

If nix is not available, skip this step — CI will verify.

- [ ] **Step 2: Build aarch64 boot image**

Run (inside `nix develop`):
```bash
cargo xtask qemu-test --target aarch64
```

Expected: All 4 milestones pass (unchanged — aarch64 was not modified).

---

### Task 4: Push and create PR

**Files:**
- No file changes.

- [ ] **Step 1: Push branch**

```bash
git push -u origin jake-os-x86-kernel-stack
```

- [ ] **Step 2: Create PR**

```bash
gh pr create --title "feat(boot): switch x86_64 to 128KB heap stack for PQ keygen" --body "$(cat <<'EOF'
## Summary

- Allocate a 128KB stack from the heap after heap init
- Assembly trampoline switches RSP before RDRAND/identity/PQ/VirtIO/event loop
- `BootState` struct carries `boot_info`, `phys_offset`, `pit` across the switch
- Removes `cfg(not(feature = "qemu-test"))` gate — PQ keygen now runs in all modes on x86_64
- aarch64 unchanged (UEFI stack is already large enough)

## Test plan

- [x] `cargo test --workspace` — all tests pass
- [x] `cargo clippy --workspace --all-targets -- -D warnings` — clean
- [ ] `cargo xtask qemu-test` — both architectures pass, PQ identity visible in x86_64 output

Closes harmony-os-wwa

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Close bead after CI passes**

```bash
bd close harmony-os-wwa --reason "x86_64 kernel now uses 128KB heap stack. PQ keygen works in all modes."
```
