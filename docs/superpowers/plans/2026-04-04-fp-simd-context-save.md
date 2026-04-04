# FP/SIMD Context Save Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add eager FP/SIMD register save/restore to every context switch path so tasks can safely use floating-point and NEON instructions.

**Architecture:** Grow TrapFrame from 272 to 800 bytes by adding FPCR, FPSR, and 32 Q registers. Update all three assembly save/restore paths (IRQ handler, SVC handler, enter_scheduler). Enable CPACR_EL1.FPEN at boot.

**Tech Stack:** Rust (no_std), AArch64 inline assembly, GICv3

**Design spec:** `docs/superpowers/specs/2026-04-04-fp-simd-context-save-design.md`

---

## File Structure

| File | Changes |
|------|---------|
| `crates/harmony-boot-aarch64/src/syscall.rs` | Add fpcr/fpsr/_pad/q fields to TrapFrame, update size/offset tests |
| `crates/harmony-boot-aarch64/src/sched.rs` | Update TRAPFRAME_SIZE from 272 to 800, update comment |
| `crates/harmony-boot-aarch64/src/vectors.rs` | Add FP save/restore to IRQ and SVC handlers, update stack alloc size |
| `crates/harmony-boot-aarch64/src/sched.rs` | Add FP restore to enter_scheduler, update stack dealloc size |
| `crates/harmony-boot-aarch64/src/main.rs` | Add CPACR_EL1.FPEN enable during boot |

---

### Task 1: TrapFrame Expansion + Tests

**Context:** The TrapFrame struct in `syscall.rs` defines the saved register layout. Assembly in `vectors.rs` and `sched.rs` uses hardcoded offsets that must match. The compile-time guard in `sched.rs` fires if the struct outgrows `TRAPFRAME_SIZE`.

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/syscall.rs:16-24` (TrapFrame struct)
- Modify: `crates/harmony-boot-aarch64/src/syscall.rs:191-215` (tests)
- Modify: `crates/harmony-boot-aarch64/src/sched.rs:40-42` (TRAPFRAME_SIZE)

- [ ] **Step 1: Write failing offset tests for new FP fields**

In `crates/harmony-boot-aarch64/src/syscall.rs`, add tests after the existing `trap_frame_spsr_offset` test (after line 214, inside the `mod tests` block):

```rust
    #[test]
    fn trap_frame_fpcr_offset() {
        assert_eq!(mem::offset_of!(TrapFrame, fpcr), 264);
    }

    #[test]
    fn trap_frame_fpsr_offset() {
        assert_eq!(mem::offset_of!(TrapFrame, fpsr), 272);
    }

    #[test]
    fn trap_frame_q_offset() {
        assert_eq!(mem::offset_of!(TrapFrame, q), 288);
    }

    #[test]
    fn trap_frame_size_with_fp() {
        // 31 GP regs (248) + elr (8) + spsr (8) + fpcr (8) + fpsr (8)
        // + _pad (8) + 32 Q regs (512) = 800
        assert_eq!(mem::size_of::<TrapFrame>(), 800);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin 2>&1`
Expected: FAIL — `fpcr`, `fpsr`, `q` fields not found on TrapFrame

- [ ] **Step 3: Add FP fields to TrapFrame**

In `crates/harmony-boot-aarch64/src/syscall.rs`, replace the TrapFrame struct (lines 16-24):

```rust
#[repr(C)]
pub struct TrapFrame {
    /// General-purpose registers X0-X30.
    pub x: [u64; 31],
    /// Exception Link Register — the PC to return to.
    pub elr: u64,
    /// Saved Processor State Register.
    pub spsr: u64,
    /// Floating-Point Control Register.
    pub fpcr: u64,
    /// Floating-Point Status Register.
    pub fpsr: u64,
    /// Padding to align `q` to 16 bytes (required for `stp`/`ldp` of Q regs).
    _pad: u64,
    /// SIMD/FP registers Q0-Q31 (128 bits each).
    pub q: [u128; 32],
}
```

- [ ] **Step 4: Update existing size test**

In `crates/harmony-boot-aarch64/src/syscall.rs`, update `trap_frame_size` test (line 192-195):

```rust
    #[test]
    fn trap_frame_size() {
        // 31 GP regs (248) + elr (8) + spsr (8) + fpcr (8) + fpsr (8)
        // + _pad (8) + 32 Q regs (512) = 800 bytes
        assert_eq!(mem::size_of::<TrapFrame>(), 800);
    }
```

- [ ] **Step 5: Update TRAPFRAME_SIZE constant in sched.rs**

In `crates/harmony-boot-aarch64/src/sched.rs`, replace lines 40-42:

```rust
/// Size of the TrapFrame in bytes (31 GP regs + ELR + SPSR + FPCR + FPSR
/// + padding + 32 Q regs = 800). Must match vectors.rs assembly.
const TRAPFRAME_SIZE: usize = 800;
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin 2>&1`
Expected: PASS (all tests including new offset tests and compile-time guard)

- [ ] **Step 7: Run clippy**

Run: `cd crates/harmony-boot-aarch64 && cargo clippy --target x86_64-apple-darwin 2>&1`
Expected: No new warnings

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-boot-aarch64/src/syscall.rs crates/harmony-boot-aarch64/src/sched.rs
git commit -m "feat(syscall): expand TrapFrame with FP/SIMD registers

Add fpcr, fpsr, and q[0..32] fields to TrapFrame. Size grows from
272 to 800 bytes. Update TRAPFRAME_SIZE constant and offset tests."
```

---

### Task 2: Assembly — FP Save/Restore in IRQ and SVC Handlers

**Context:** Both `el1_irq_handler` and `el1_sync_handler` in `vectors.rs` save/restore the TrapFrame using hardcoded assembly. They need FP register save/restore added and the stack allocation size updated from 272 to 800.

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/vectors.rs:107-174` (SVC handler)
- Modify: `crates/harmony-boot-aarch64/src/vectors.rs:184-236` (IRQ handler)

**Important:** Both handlers follow the identical pattern. The FP save goes after the GP save (after `stp x10, x11, [sp, #248]` which saves ELR/SPSR). The FP restore goes before the GP restore (before `ldp x10, x11, [sp, #248]` which loads ELR/SPSR).

- [ ] **Step 1: Update el1_sync_handler (SVC) — save path**

In `vectors.rs`, find `el1_sync_handler:` (line 107). Make these changes:

1. Change `"sub sp, sp, #272"` to `"sub sp, sp, #800"`

2. After `"stp x10, x11, [sp, #248]"` (line 131, saves ELR/SPSR), add the FP save block:

```asm
// Save FPCR and FPSR
"mrs x10, fpcr",
"mrs x11, fpsr",
"stp x10, x11, [sp, #264]",
// Save Q0-Q31 (32 SIMD regs, 128 bits each, at offset 288)
"stp q0,  q1,  [sp, #288]",
"stp q2,  q3,  [sp, #320]",
"stp q4,  q5,  [sp, #352]",
"stp q6,  q7,  [sp, #384]",
"stp q8,  q9,  [sp, #416]",
"stp q10, q11, [sp, #448]",
"stp q12, q13, [sp, #480]",
"stp q14, q15, [sp, #512]",
"stp q16, q17, [sp, #544]",
"stp q18, q19, [sp, #576]",
"stp q20, q21, [sp, #608]",
"stp q22, q23, [sp, #640]",
"stp q24, q25, [sp, #672]",
"stp q26, q27, [sp, #704]",
"stp q28, q29, [sp, #736]",
"stp q30, q31, [sp, #768]",
```

- [ ] **Step 2: Update el1_sync_handler (SVC) — restore path**

In the SVC restore section (after `call_svc_handler:` / `bl svc_handler`), BEFORE the line `"ldp x10, x11, [sp, #248]"` (which restores ELR/SPSR), add:

```asm
// Restore Q0-Q31
"ldp q0,  q1,  [sp, #288]",
"ldp q2,  q3,  [sp, #320]",
"ldp q4,  q5,  [sp, #352]",
"ldp q6,  q7,  [sp, #384]",
"ldp q8,  q9,  [sp, #416]",
"ldp q10, q11, [sp, #448]",
"ldp q12, q13, [sp, #480]",
"ldp q14, q15, [sp, #512]",
"ldp q16, q17, [sp, #544]",
"ldp q18, q19, [sp, #576]",
"ldp q20, q21, [sp, #608]",
"ldp q22, q23, [sp, #640]",
"ldp q24, q25, [sp, #672]",
"ldp q26, q27, [sp, #704]",
"ldp q28, q29, [sp, #736]",
"ldp q30, q31, [sp, #768]",
// Restore FPCR and FPSR
"ldp x10, x11, [sp, #264]",
"msr fpcr, x10",
"msr fpsr, x11",
```

3. Change `"add sp, sp, #272"` (dealloc) to `"add sp, sp, #800"`

- [ ] **Step 3: Update el1_irq_handler — save path**

In `vectors.rs`, find `el1_irq_handler:` (line 184). Make the same changes:

1. Change `"sub sp, sp, #272"` to `"sub sp, sp, #800"`

2. After `"stp x10, x11, [sp, #248]"` (line 208, saves ELR/SPSR), add the identical FP save block:

```asm
// Save FPCR and FPSR
"mrs x10, fpcr",
"mrs x11, fpsr",
"stp x10, x11, [sp, #264]",
// Save Q0-Q31
"stp q0,  q1,  [sp, #288]",
"stp q2,  q3,  [sp, #320]",
"stp q4,  q5,  [sp, #352]",
"stp q6,  q7,  [sp, #384]",
"stp q8,  q9,  [sp, #416]",
"stp q10, q11, [sp, #448]",
"stp q12, q13, [sp, #480]",
"stp q14, q15, [sp, #512]",
"stp q16, q17, [sp, #544]",
"stp q18, q19, [sp, #576]",
"stp q20, q21, [sp, #608]",
"stp q22, q23, [sp, #640]",
"stp q24, q25, [sp, #672]",
"stp q26, q27, [sp, #704]",
"stp q28, q29, [sp, #736]",
"stp q30, q31, [sp, #768]",
```

- [ ] **Step 4: Update el1_irq_handler — restore path**

BEFORE `"ldp x10, x11, [sp, #248]"` (which restores ELR/SPSR in the IRQ handler), add the identical FP restore block:

```asm
// Restore Q0-Q31
"ldp q0,  q1,  [sp, #288]",
"ldp q2,  q3,  [sp, #320]",
"ldp q4,  q5,  [sp, #352]",
"ldp q6,  q7,  [sp, #384]",
"ldp q8,  q9,  [sp, #416]",
"ldp q10, q11, [sp, #448]",
"ldp q12, q13, [sp, #480]",
"ldp q14, q15, [sp, #512]",
"ldp q16, q17, [sp, #544]",
"ldp q18, q19, [sp, #576]",
"ldp q20, q21, [sp, #608]",
"ldp q22, q23, [sp, #640]",
"ldp q24, q25, [sp, #672]",
"ldp q26, q27, [sp, #704]",
"ldp q28, q29, [sp, #736]",
"ldp q30, q31, [sp, #768]",
// Restore FPCR and FPSR
"ldp x10, x11, [sp, #264]",
"msr fpcr, x10",
"msr fpsr, x11",
```

3. Change `"add sp, sp, #272"` to `"add sp, sp, #800"`

- [ ] **Step 5: Update assembly comments**

Update the comments that reference "272" or "264 bytes":
- Line 108: `"// Allocate TrapFrame on the stack (264 bytes, rounded up to 272..."` → `"// Allocate TrapFrame on the stack (800 bytes: GP + ELR/SPSR + FP/SIMD)"`
- Line 185: `"// Allocate TrapFrame (264 bytes, padded to 272..."` → `"// Allocate TrapFrame (800 bytes: GP + ELR/SPSR + FP/SIMD)"`

- [ ] **Step 6: Verify compilation**

Run: `cd crates/harmony-boot-aarch64 && cargo check --target aarch64-unknown-uefi 2>&1`
Expected: PASS (this is the only way to verify the assembly is valid — host tests don't compile aarch64 assembly)

Run: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin 2>&1`
Expected: PASS (no regressions on host tests)

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-boot-aarch64/src/vectors.rs
git commit -m "feat(vectors): add FP/SIMD save/restore to IRQ and SVC handlers

Save/restore FPCR, FPSR, and Q0-Q31 in both el1_irq_handler and
el1_sync_handler. Stack allocation grows from 272 to 800 bytes."
```

---

### Task 3: enter_scheduler FP Restore + CPACR_EL1 Enable

**Context:** `enter_scheduler` in `sched.rs` loads task 0's TrapFrame and erets into it. It needs the FP restore path (not save). Also, CPACR_EL1.FPEN must be enabled at boot before any FP instruction executes.

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/sched.rs:280-323` (enter_scheduler)
- Modify: `crates/harmony-boot-aarch64/src/main.rs` (CPACR enable, early in boot)

- [ ] **Step 1: Update enter_scheduler FP restore**

In `crates/harmony-boot-aarch64/src/sched.rs`, find the `enter_scheduler` function (line 280). The inline assembly loads ELR/SPSR, then GP regs, then deallocates and erets.

Add FP restore BEFORE the ELR/SPSR restore (before `"ldp x10, x11, [sp, #248]"`):

```asm
// Restore Q0-Q31 from task 0's TrapFrame.
"ldp q0,  q1,  [sp, #288]",
"ldp q2,  q3,  [sp, #320]",
"ldp q4,  q5,  [sp, #352]",
"ldp q6,  q7,  [sp, #384]",
"ldp q8,  q9,  [sp, #416]",
"ldp q10, q11, [sp, #448]",
"ldp q12, q13, [sp, #480]",
"ldp q14, q15, [sp, #512]",
"ldp q16, q17, [sp, #544]",
"ldp q18, q19, [sp, #576]",
"ldp q20, q21, [sp, #608]",
"ldp q22, q23, [sp, #640]",
"ldp q24, q25, [sp, #672]",
"ldp q26, q27, [sp, #704]",
"ldp q28, q29, [sp, #736]",
"ldp q30, q31, [sp, #768]",
// Restore FPCR and FPSR.
"ldp x10, x11, [sp, #264]",
"msr fpcr, x10",
"msr fpsr, x11",
```

Also change `"add sp, sp, #272"` to `"add sp, sp, #800"`.

- [ ] **Step 2: Enable CPACR_EL1.FPEN at boot**

In `crates/harmony-boot-aarch64/src/main.rs`, find the MMU init section (around line 318: `// ── Build identity map and enable MMU ──`). BEFORE this line (so FP is available before any code that might use it), add:

```rust
    // Enable FP/SIMD access at EL1 and EL0. CPACR_EL1.FPEN [21:20] = 0b11.
    // Must be done before any code uses floating-point (including memcpy
    // optimizations in musl libc). Reset value is IMPLEMENTATION DEFINED.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            "mrs {tmp}, CPACR_EL1",
            "orr {tmp}, {tmp}, #(0x3 << 20)",
            "msr CPACR_EL1, {tmp}",
            "isb",
            tmp = out(reg) _,
        );
    }
    let _ = writeln!(serial, "[FP] SIMD/FP access enabled (CPACR_EL1.FPEN)");
```

Note: Uses read-modify-write (`mrs` + `orr` + `msr`) instead of a plain `msr` to preserve other CPACR_EL1 fields (e.g., ZEN for SVE, if set by firmware).

- [ ] **Step 3: Update sched.rs module doc comment**

In `crates/harmony-boot-aarch64/src/sched.rs`, the module doc comment (lines 12-14) says:

```rust
//! - No FP/SIMD context save — tasks must not use floating-point.
//!   FP context switch will be added no later than Phase 4; see design spec
//!   section 8 for options (eager vs lazy save via CPACR_EL1.FPEN).
```

Replace with:

```rust
//! - Eager FP/SIMD context save: all 32 Q registers + FPCR + FPSR are
//!   saved/restored on every context switch.
```

- [ ] **Step 4: Verify compilation and tests**

Run: `cd crates/harmony-boot-aarch64 && cargo check --target aarch64-unknown-uefi 2>&1`
Expected: PASS

Run: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin 2>&1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-boot-aarch64/src/sched.rs crates/harmony-boot-aarch64/src/main.rs
git commit -m "feat(boot): FP restore in enter_scheduler + CPACR_EL1.FPEN at boot

enter_scheduler restores Q0-Q31 + FPCR/FPSR from task 0's TrapFrame.
CPACR_EL1.FPEN enabled early in boot so all tasks can use FP/SIMD."
```

---

## Post-Implementation Checklist

- [ ] Run full test suite: `cd crates/harmony-boot-aarch64 && cargo test --target x86_64-apple-darwin`
- [ ] Run clippy: `cd crates/harmony-boot-aarch64 && cargo clippy --target x86_64-apple-darwin`
- [ ] Cross-compile check: `cd crates/harmony-boot-aarch64 && cargo check --target aarch64-unknown-uefi`
- [ ] Run nightly rustfmt: `cargo +nightly fmt --all -- --check`
- [ ] QEMU boot test: `cargo +nightly xtask qemu-test --target aarch64 --timeout 60`
- [ ] Verify no `272` references remain in assembly: `grep -n "272" crates/harmony-boot-aarch64/src/vectors.rs crates/harmony-boot-aarch64/src/sched.rs`
