// SPDX-License-Identifier: GPL-2.0-or-later
//! Aarch64 exception vector table (VBAR_EL1).
//!
//! Provides a 2048-byte aligned vector table with 16 entries. Only the
//! "Current EL with SPx, Synchronous" entry (offset 0x200) has real
//! dispatch logic — it reads ESR_EL1 to determine the exception class
//! and branches to the appropriate Rust handler. All other entries halt
//! with an unexpected-exception panic.

#![cfg_attr(not(target_arch = "aarch64"), allow(dead_code, unused_imports))]

/// Install the exception vector table.
///
/// Writes VBAR_EL1 to point to our vector table and issues an ISB to
/// ensure the new value takes effect before the next exception.
///
/// # Safety
/// Must be called once, at EL1, before any SVC or fault can occur.
#[cfg(target_arch = "aarch64")]
pub unsafe fn init() {
    core::arch::asm!(
        "adr {tmp}, vector_table",
        "msr vbar_el1, {tmp}",
        "isb",
        tmp = out(reg) _,
    );
}

/// The exception vector table and its entries.
///
/// Each entry is exactly 128 bytes (0x80). The table is 2048 bytes
/// total (16 entries) and must be 2048-byte aligned.
///
/// The 0x200 entry (Current EL, SPx, Synchronous) branches to an
/// out-of-line handler (`el1_sync_handler`) that saves the full
/// TrapFrame and dispatches SVC/abort. All handler code lives
/// outside the table to avoid overflowing the 128-byte slot.
///
/// Layout:
///   0x000  Current EL, SP_EL0, Synchronous   — unused (we use SPx)
///   0x080  Current EL, SP_EL0, IRQ           — unused
///   0x100  Current EL, SP_EL0, FIQ           — unused
///   0x180  Current EL, SP_EL0, SError        — unused
///   0x200  Current EL, SPx, Synchronous      — branch to el1_sync_handler
///   0x280  Current EL, SPx, IRQ              — unexpected
///   0x300  Current EL, SPx, FIQ              — unexpected
///   0x380  Current EL, SPx, SError           — unexpected
///   0x400-0x780  Lower EL entries             — all unused
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    // ── Vector table ────────────────────────────────────────────
    ".balign 2048",
    "vector_table:",

    // 0x000 — Current EL, SP_EL0, Synchronous (unused)
    "b unexpected_exception",
    ".balign 0x80",

    // 0x080 — Current EL, SP_EL0, IRQ (unused)
    "b unexpected_exception",
    ".balign 0x80",

    // 0x100 — Current EL, SP_EL0, FIQ (unused)
    "b unexpected_exception",
    ".balign 0x80",

    // 0x180 — Current EL, SP_EL0, SError (unused)
    "b unexpected_exception",
    ".balign 0x80",

    // ── 0x200 — Current EL, SPx, Synchronous ── THE MAIN ENTRY ──
    // Branch out-of-line: handler body exceeds the 128-byte entry slot.
    "b el1_sync_handler",
    ".balign 0x80",

    // 0x280 — Current EL, SPx, IRQ (unexpected)
    "b unexpected_exception",
    ".balign 0x80",

    // 0x300 — Current EL, SPx, FIQ (unexpected)
    "b unexpected_exception",
    ".balign 0x80",

    // 0x380 — Current EL, SPx, SError (unexpected)
    "b unexpected_exception",
    ".balign 0x80",

    // 0x400-0x780 — Lower EL entries (8 entries, all unused)
    "b unexpected_exception",
    ".balign 0x80",
    "b unexpected_exception",
    ".balign 0x80",
    "b unexpected_exception",
    ".balign 0x80",
    "b unexpected_exception",
    ".balign 0x80",
    "b unexpected_exception",
    ".balign 0x80",
    "b unexpected_exception",
    ".balign 0x80",
    "b unexpected_exception",
    ".balign 0x80",
    "b unexpected_exception",
    ".balign 0x80",

    // ── Unexpected exception handler ────────────────────────────
    "unexpected_exception:",
    "b unexpected_exception",  // infinite loop

    // ── Out-of-line synchronous exception handler ─────────────
    // Lives outside the vector table so it doesn't overflow the
    // 128-byte entry at 0x200.

    "el1_sync_handler:",

    // Allocate TrapFrame on the stack (264 bytes, rounded up to 272 for 16-byte alignment)
    "sub sp, sp, #272",

    // Save X0-X29 as pairs
    "stp x0,  x1,  [sp, #0]",
    "stp x2,  x3,  [sp, #16]",
    "stp x4,  x5,  [sp, #32]",
    "stp x6,  x7,  [sp, #48]",
    "stp x8,  x9,  [sp, #64]",
    "stp x10, x11, [sp, #80]",
    "stp x12, x13, [sp, #96]",
    "stp x14, x15, [sp, #112]",
    "stp x16, x17, [sp, #128]",
    "stp x18, x19, [sp, #144]",
    "stp x20, x21, [sp, #160]",
    "stp x22, x23, [sp, #176]",
    "stp x24, x25, [sp, #192]",
    "stp x26, x27, [sp, #208]",
    "stp x28, x29, [sp, #224]",
    // Save X30 (LR)
    "str x30, [sp, #240]",
    // Save ELR_EL1 and SPSR_EL1
    "mrs x10, elr_el1",
    "mrs x11, spsr_el1",
    "stp x10, x11, [sp, #248]",

    // Read ESR_EL1 for exception class
    "mrs x1, esr_el1",
    // EC = ESR[31:26]
    "lsr x2, x1, #26",

    // EC == 0x15 → SVC from AArch64
    "cmp x2, #0x15",
    "b.eq call_svc_handler",

    // EC == 0x25 → Data Abort, current EL
    "cmp x2, #0x25",
    "b.eq call_abort_handler",

    // EC == 0x21 → Instruction Abort, current EL
    "cmp x2, #0x21",
    "b.eq call_abort_handler",

    // Other — fall through to abort handler with ESR in x1
    "b call_abort_handler",

    // ── SVC handler dispatch ──
    "call_svc_handler:",
    "mov x0, sp",              // x0 = &TrapFrame
    "bl svc_handler",          // svc_handler(&mut TrapFrame)

    // Restore ELR and SPSR
    "ldp x10, x11, [sp, #248]",
    "msr elr_el1, x10",
    "msr spsr_el1, x11",

    // Restore X0-X29
    "ldp x0,  x1,  [sp, #0]",
    "ldp x2,  x3,  [sp, #16]",
    "ldp x4,  x5,  [sp, #32]",
    "ldp x6,  x7,  [sp, #48]",
    "ldp x8,  x9,  [sp, #64]",
    "ldp x10, x11, [sp, #80]",
    "ldp x12, x13, [sp, #96]",
    "ldp x14, x15, [sp, #112]",
    "ldp x16, x17, [sp, #128]",
    "ldp x18, x19, [sp, #144]",
    "ldp x20, x21, [sp, #160]",
    "ldp x22, x23, [sp, #176]",
    "ldp x24, x25, [sp, #192]",
    "ldp x26, x27, [sp, #208]",
    "ldp x28, x29, [sp, #224]",
    "ldr x30, [sp, #240]",

    // Deallocate TrapFrame
    "add sp, sp, #272",
    "eret",

    // ── Abort handler dispatch ──
    "call_abort_handler:",
    "mov x0, sp",              // x0 = &TrapFrame
    // x1 already contains ESR_EL1 from above
    "bl abort_handler",        // abort_handler(&TrapFrame, esr: u64) -> !
    "b unexpected_exception",  // should not return, but safety net
);
