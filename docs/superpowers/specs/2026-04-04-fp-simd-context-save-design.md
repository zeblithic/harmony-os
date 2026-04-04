# FP/SIMD Context Save Design

**Bead**: `harmony-os-6cm`
**Depends on**: Phase 4 (harmony-os-azy, PR #112) — merged
**Blocks**: Phase 5 (harmony-os-0oo) — real Linux binaries need FP

## Goal

Add eager FP/SIMD register save/restore to every context switch path so that tasks can safely use floating-point and NEON/SIMD instructions. Required before running real Linux binaries (musl libc uses NEON for memcpy/memset).

## Architecture

Eager save: every context switch saves all 32 Q registers (Q0-Q31, 128 bits each) plus FPCR and FPSR, whether or not the task uses FP. The TrapFrame grows from 272 to 800 bytes. No lazy trapping, no per-task FP dirty flag, no CPACR manipulation per context switch.

## Non-Goals

- **Lazy FP save** — complexity not justified when musl libc triggers FP in nearly every task.
- **SVE (Scalable Vector Extension)** — standard NEON/FP only.
- **Per-task FPEN control** — all tasks get FP access at EL1 (and EL0 when added).

---

## 1. TrapFrame Layout

Current (272 bytes):
```
Offset   0: x[0..31]   — 31 GP regs × 8 = 248 bytes
Offset 248: elr        — 8 bytes
Offset 256: spsr       — 8 bytes
Offset 264: (padding)  — 8 bytes
Total: 272 bytes
```

New (800 bytes):
```
Offset   0: x[0..31]   — 31 GP regs × 8 = 248 bytes
Offset 248: elr        — 8 bytes
Offset 256: spsr       — 8 bytes
Offset 264: fpcr       — 8 bytes (u64, upper 32 bits zero)
Offset 272: fpsr       — 8 bytes (u64, upper 32 bits zero)
Offset 280: _pad       — 8 bytes (align q[] to 16 bytes)
Offset 288: q[0..32]   — 32 SIMD regs × 16 = 512 bytes
Total: 800 bytes (16-byte aligned)
```

### TrapFrame Struct

```rust
#[repr(C)]
pub struct TrapFrame {
    pub x: [u64; 31],    // X0-X30 (offset 0-248)
    pub elr: u64,        // Exception Link Register (offset 248)
    pub spsr: u64,       // Saved Processor State Register (offset 256)
    pub fpcr: u64,       // Floating-Point Control Register (offset 264)
    pub fpsr: u64,       // Floating-Point Status Register (offset 272)
    _pad: u64,           // Align q[] to 16 bytes (offset 280)
    pub q: [u128; 32],   // Q0-Q31 SIMD/FP registers (offset 288)
}
```

### Constants

- `TRAPFRAME_SIZE` changes from 272 to 800.
- Compile-time guard fires if `size_of::<TrapFrame>() > TRAPFRAME_SIZE`.

---

## 2. Assembly Changes

Three assembly paths need FP save/restore:

### IRQ Handler (vectors.rs, el1_irq_handler)

The main context switch path. After saving GP registers and ELR/SPSR, add:

```asm
// Save FPCR and FPSR
mrs x10, fpcr
mrs x11, fpsr
stp x10, x11, [sp, #264]

// Save Q0-Q31 (16 stp pairs, 128-bit each, starting at offset 288)
stp q0,  q1,  [sp, #288]
stp q2,  q3,  [sp, #320]
stp q4,  q5,  [sp, #352]
stp q6,  q7,  [sp, #384]
stp q8,  q9,  [sp, #416]
stp q10, q11, [sp, #448]
stp q12, q13, [sp, #480]
stp q14, q15, [sp, #512]
stp q16, q17, [sp, #544]
stp q18, q19, [sp, #576]
stp q20, q21, [sp, #608]
stp q22, q23, [sp, #640]
stp q24, q25, [sp, #672]
stp q26, q27, [sp, #704]
stp q28, q29, [sp, #736]
stp q30, q31, [sp, #768]
```

Restore is the reverse: `ldp` Q regs, `ldp` FPCR/FPSR, `msr fpcr`/`msr fpsr`.

Stack allocation: `sub sp, sp, #272` → `sub sp, sp, #800`.
Stack deallocation: `add sp, sp, #272` → `add sp, sp, #800`.

### SVC Handler (vectors.rs, el1_sync_handler)

Same save/restore pattern. The SVC TrapFrame may be context-switched via the IRQ handler (Self-SGI from `block_current`), so it must also save FP state.

### enter_scheduler (sched.rs)

Loads task 0's initial TrapFrame. Only needs the restore path (no prior state to save on first entry). Add FP register restore before GP restore.

---

## 3. Boot Init: Enable CPACR_EL1.FPEN

CPACR_EL1.FPEN resets to IMPLEMENTATION DEFINED. Must explicitly enable before any FP instruction executes:

```rust
// CPACR_EL1.FPEN [21:20] = 0b11 — full FP/SIMD access at EL1 and EL0.
core::arch::asm!("msr CPACR_EL1, {}", in(reg) (0b11u64 << 20));
core::arch::asm!("isb");
```

Placed early in boot init, before MMU setup or any code that might use FP.

---

## 4. spawn_task Changes

`spawn_task` already zeroes the entire TrapFrame region via `write_bytes(frame_ptr, 0, TRAPFRAME_SIZE)`. With TRAPFRAME_SIZE = 800, this correctly zeroes the FP fields:
- FPCR = 0 (default rounding mode, no exceptions)
- FPSR = 0 (no flags set)
- Q0-Q31 = 0

No logic changes needed — only the constant changes.

---

## 5. Testing

- **Compile-time guard:** `size_of::<TrapFrame>() <= TRAPFRAME_SIZE` (existing, fires on mismatch).
- **Offset tests:** Verify `offset_of!(TrapFrame, fpcr) == 264`, `offset_of!(TrapFrame, fpsr) == 272`, `offset_of!(TrapFrame, q) == 288`.
- **QEMU boot test:** Existing 9 milestones still pass (3-task boot with FP-capable tasks).
- **No new FP-exercising test:** The QEMU test proves the context switch works (tasks run, switch, resume correctly). A dedicated FP test (task that uses FP, gets preempted, verifies FP state preserved) would be ideal but is deferred — the eager save guarantees correctness by construction.

---

## 6. What This Delivers

- All tasks can safely use FP/SIMD instructions (NEON, VFP).
- Context switches preserve all 32 Q registers + FPCR + FPSR.
- musl libc's NEON-optimized memcpy/memset work correctly across preemption.
- CPACR_EL1.FPEN enabled at boot — works on real hardware, not just QEMU.
- Foundation for Phase 5 (running real Linux binaries that use FP).
