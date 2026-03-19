# x86_64 Kernel Stack Switch — Design

**Date:** 2026-03-19
**Status:** Implemented (stack switch); PQ keygen deferred (see harmony-os-0vp)
**Bead:** harmony-os-wwa

## Problem

The `bootloader` crate (v0.11) provides a ~16KB kernel stack on x86_64. This is sufficient for Ed25519 key generation (curve25519-dalek is stack-efficient) but too small for post-quantum cryptography. ML-KEM-768 key generation creates NTT polynomial matrices (~10KB of stack intermediates), and ML-DSA-65 key generation uses even larger lattice structures (~15KB). Combined, they overflow the bootloader stack, causing a triple fault with no serial output.

aarch64 is unaffected — UEFI firmware provides a ~128KB+ stack.

**Current state:** The stack switch is implemented and working. PQ keygen on x86_64 is disabled pending investigation of a separate codegen issue (harmony-os-0vp) — PQ keygen triple-faults on `x86_64-unknown-none` even with 512KB stack and 3.5MB free heap, suspected keccak/sha3 codegen incompatibility with the soft-float bare-metal target. PQ keygen works on aarch64.

## Solution

Switch the kernel to a heap-allocated 512KB stack immediately after heap initialization. All subsequent boot code — PIT timer, entropy, identity generation (Ed25519), VirtIO, netstack, event loop — runs on the new stack.

## Architecture

### Boot Sequence (After)

```
kernel_main(boot_info):                          ← bootloader stack (~16KB)
  1. serial_init()
  2. physical memory offset
  3. heap init (4MB)
  4. PIT timer init
  5. allocate 512KB stack from heap (forget the Vec)
  6. pack BootState into Box on heap
  7. asm trampoline: switch RSP, call kernel_continue
     ── stack boundary ──
kernel_continue(state: *mut BootState):          ← heap stack (512KB)
  8. unpack BootState
  9. RDRAND / entropy
  10. identity generation (Ed25519)
  11. PQ identity — disabled on x86_64 pending harmony-os-0vp
  12. VirtIO, netstack
  13. register destinations, event loop (never returns)
```

### BootState Struct

State from early boot that must survive the stack switch. All early-boot locals live on the bootloader stack and become inaccessible after RSP changes. BootState is heap-allocated (`Box`) so its pointer remains valid.

```rust
struct BootState {
    boot_info: &'static mut BootInfo,
    phys_offset: u64,
    pit: PitTimer,
    stack_canary_addr: usize,
}
```

`heap_size` is not carried — it is only used for the `[HEAP]` log line in `kernel_main`, before the switch.

`PitTimer` has accumulated state (`accumulated_ticks`, `last_count`) that must be preserved — it cannot be reconstructed from hardware registers. `serial` is reconstructed via `serial_writer()` which creates a stateless closure over port I/O.

### Assembly Trampoline

Minimal x86_64 assembly. Takes three arguments (SysV ABI):
- `rdi` — pointer to BootState (first arg to continuation)
- `rsi` — new stack top (512KB allocation + size, 16-byte aligned)
- `rdx` — continuation function pointer

```asm
switch_to_stack:
    mov rsp, rsi       // switch to new stack (16-byte aligned)
    call rdx           // call kernel_continue(state)
                       // call pushes 8-byte return address → RSP is
                       // 16n-8 at callee entry, which is the correct
                       // SysV ABI state (callee does push rbp → 16n)
    ud2                // unreachable — kernel_continue is -> !
```

No `sub rsp, 8` before `call` — the `call` instruction itself provides the -8 offset that the SysV ABI expects at function entry.

### Stack Layout

```
heap base          ┌─────────────────────┐
                   │  512 KiB zeroed     │
                   │  (grows downward)   │
                   │                     │
                   │  ┌─── RSP after ──┐ │
                   │  │    switch      │ │
heap base + 512K   └──┴───────────────┴──┘  ← stack_top (16-byte aligned)
```

- **Size:** 512KB. ML-KEM + ML-DSA together need ~25KB of stack for intermediates. 512KB provides ~20x headroom for future PQ operations (the four-layer key hierarchy, Nakaiah's integrity chains). Uses 12.5% of the 4MB heap.
- **Alignment:** `(heap_alloc_ptr + 512KB) & !0xF` — required by x86_64 SysV ABI. `Vec<u8>` has 1-byte alignment, so the base may be at any address. The `& !0xF` mask rounds down by at most 15 bytes, which is always within the 512KB allocation.
- **Zero-fill:** `alloc::vec![0u8; KERNEL_STACK_SIZE]` — stack overflows hit zeroed memory. A canary word (`0xDEAD_BEEF_CAFE_BABE`) is written at the stack base and checked via `debug_assert` in the event loop.
- **Lifetime:** The `Vec<u8>` backing the stack must never be dropped — it is the kernel's permanent stack. Use `core::mem::forget(stack_vec)` after computing `stack_top` to prevent the destructor from ever freeing the stack memory.

### What Changes

| File | Change |
|------|--------|
| `crates/harmony-boot/src/main.rs` | Split `kernel_main` into early-boot (steps 1-7) and `kernel_continue` (steps 8+). Add `BootState` struct. Add `switch_to_stack` asm. Move PIT init before the switch. PQ keygen disabled pending harmony-os-0vp. |

### What Does NOT Change

- `harmony-unikernel` — `UnikernelRuntime`, `generate_pq_identity()` unchanged.
- `harmony-boot-aarch64` — UEFI stack is large enough, no switch needed.
- `xtask/src/qemu_test.rs` — milestones unchanged.
- Panic handler — uses `serial_init()` + port I/O. On the heap stack (post-switch), the panic handler has 512KB of stack space. On the bootloader stack (pre-switch), it has ~16KB — same as today, not a regression.

## Testing

| Test | Verifies |
|------|----------|
| `cargo test --workspace` | All 900+ tests pass (no boot crate changes affect lib tests) |
| `cargo clippy --workspace` | Clean |
| `cargo xtask qemu-test --target x86_64` | Kernel boots on heap stack, all 4 milestones pass (PQ keygen skipped) |
| `cargo xtask qemu-test --target aarch64` | Unchanged — still passes (PQ keygen runs) |

## Alternatives Considered

**B: `run_on_stack` wrapper for PQ only.** Allocate a temporary stack, run a closure on it, switch back. Lower blast radius but doesn't help future stack-hungry operations. Rejected because the kernel should own its stack — depending on the bootloader's stack for the entire kernel lifetime is fragile.

**C: `bootloader` crate stack size config.** The `bootloader` v0.11 `BootloaderConfig` struct has no stack size field. Would require forking or upgrading the bootloader. Rejected — the stack switch is simpler and bootloader-independent.
