// SPDX-License-Identifier: GPL-2.0-or-later
//! GICv3 interrupt controller driver (minimal — timer PPI only).
//!
//! Initializes the GICv3 Distributor, Redistributor, and CPU Interface
//! to route the ARM physical timer interrupt (PPI 30, INTID 30) to EL1.
//! Provides [`ack`] and [`eoi`] for the IRQ handler.

#![cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]

use core::ptr::{read_volatile, write_volatile};

// ── Distributor (GICD) register offsets ─────────────────────────────────
const GICD_CTLR: usize = 0x0000;

// GICD_CTLR bits
const GICD_CTLR_ARE_NS: u32 = 1 << 4;
const GICD_CTLR_ENABLE_GRP1_NS: u32 = 1 << 1;
const GICD_CTLR_RWP: u32 = 1 << 31;

// ── Redistributor (GICR) register offsets ───────────────────────────────
const GICR_WAKER: usize = 0x0014;

// GICR_WAKER bits
const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

// SGI_base frame: GICR base + 0x10000
const GICR_SGI_OFFSET: usize = 0x1_0000;
const GICR_IGROUPR0: usize = GICR_SGI_OFFSET + 0x0080;
const GICR_ISENABLER0: usize = GICR_SGI_OFFSET + 0x0100;
const GICR_IPRIORITYR: usize = GICR_SGI_OFFSET + 0x0400;

/// Physical timer PPI (INTID 30).
pub const TIMER_INTID: u32 = 30;

/// Spurious interrupt — returned by `ack()` when no valid interrupt is pending.
pub const SPURIOUS: u32 = 1023;

/// SGI used for voluntary yield from block_current().
/// SGI 0 is reserved by convention; we use SGI 1.
pub const YIELD_SGI: u32 = 1;

/// Initialize the GICv3 for timer interrupt delivery.
///
/// Enables the Distributor (Group 1 NS, affinity routing), wakes the
/// Redistributor, configures PPI 30 (physical timer) as Group 1 with
/// priority 0, and enables the CPU Interface.
///
/// # Safety
///
/// - Must be called exactly once, at EL1, before unmasking IRQs (DAIF.I).
/// - `gicd_base` must point to the GICv3 Distributor MMIO region.
/// - `gicr_base` must point to the GICv3 Redistributor MMIO region for
///   the current CPU.
/// - Both regions must be mapped as Device memory (NO_CACHE) by the MMU.
#[cfg(target_arch = "aarch64")]
pub unsafe fn init(gicd_base: *mut u8, gicr_base: *mut u8) {
    // ── 1. Distributor ──────────────────────────────────────────────────
    let ctlr = gicd_base.add(GICD_CTLR) as *mut u32;
    write_volatile(ctlr, GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_GRP1_NS);
    // Wait for register write to propagate.
    for _ in 0..1_000_000u32 {
        if read_volatile(ctlr) & GICD_CTLR_RWP == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    assert!(
        read_volatile(ctlr) & GICD_CTLR_RWP == 0,
        "GIC: GICD_CTLR.RWP never cleared — wrong GICD base address?"
    );

    // ── 2. Redistributor ────────────────────────────────────────────────
    // Wake the redistributor.
    let waker = gicr_base.add(GICR_WAKER) as *mut u32;
    let w = read_volatile(waker);
    write_volatile(waker, w & !GICR_WAKER_PROCESSOR_SLEEP);
    for _ in 0..1_000_000u32 {
        if read_volatile(waker) & GICR_WAKER_CHILDREN_ASLEEP == 0 {
            break;
        }
        core::hint::spin_loop();
    }
    assert!(
        read_volatile(waker) & GICR_WAKER_CHILDREN_ASLEEP == 0,
        "GIC: GICR_WAKER.ChildrenAsleep never cleared — wrong GICR base address?"
    );

    // Configure PPI 30 in the SGI_base frame.
    // Set to Group 1 NS (bit 30 of IGROUPR0).
    let igroupr0 = gicr_base.add(GICR_IGROUPR0) as *mut u32;
    write_volatile(igroupr0, read_volatile(igroupr0) | (1 << TIMER_INTID));

    // Set priority 0 (highest) for INTID 30.
    // IPRIORITYR is byte-addressable — one byte per INTID.
    let priority = gicr_base.add(GICR_IPRIORITYR + TIMER_INTID as usize) as *mut u8;
    write_volatile(priority, 0);

    // Enable INTID 30 (write-1-to-set in ISENABLER0).
    let isenabler0 = gicr_base.add(GICR_ISENABLER0) as *mut u32;
    write_volatile(isenabler0, 1 << TIMER_INTID);

    // ── 3. CPU Interface (ICC system registers) ─────────────────────────
    // Allow all interrupt priorities.
    core::arch::asm!("msr ICC_PMR_EL1, {}", in(reg) 0xFF_u64);
    // Enable Group 1 interrupts.
    core::arch::asm!("msr ICC_IGRPEN1_EL1, {}", in(reg) 1_u64);
    // Ensure all writes are visible before returning.
    core::arch::asm!("isb");
}

/// Acknowledge an interrupt — read ICC_IAR1_EL1.
///
/// Returns the INTID of the highest-priority pending interrupt, or
/// [`SPURIOUS`] (1023) if no interrupt is pending. Between `ack()` and
/// [`eoi`], the CPU's running priority is raised to the acknowledged
/// interrupt's priority, preventing same-or-lower priority interrupts
/// from nesting.
#[cfg(target_arch = "aarch64")]
pub fn ack() -> u32 {
    let intid: u64;
    unsafe { core::arch::asm!("mrs {}, ICC_IAR1_EL1", out(reg) intid) };
    intid as u32
}

/// Signal end-of-interrupt — write ICC_EOIR1_EL1.
///
/// Drops the CPU's running priority so the GIC can deliver further
/// interrupts. Must be called for every non-spurious INTID returned
/// by [`ack`]. Writing [`SPURIOUS`] to EOIR is architecturally
/// UNPREDICTABLE — never call `eoi(1023)`.
#[cfg(target_arch = "aarch64")]
pub fn eoi(intid: u32) {
    unsafe { core::arch::asm!("msr ICC_EOIR1_EL1, {}", in(reg) intid as u64) };
}

/// Send a Software Generated Interrupt to the current PE (self).
///
/// Used by `block_current()` to trigger a reschedule through the normal
/// IRQ handler path. The SGI fires immediately (tasks run with IRQs
/// unmasked), enters the IRQ handler, saves the TrapFrame, and calls
/// `schedule()`.
///
/// # Safety
///
/// Must be called with IRQs unmasked (PSTATE.I = 0).
#[cfg(target_arch = "aarch64")]
pub unsafe fn send_sgi_self(intid: u32) {
    // ICC_SGI1_EL1 format:
    //   [27:24] = INTID (SGI number, 0-15)
    //   [23:16] = Aff3 = 0
    //   [15:0]  = TargetList = 1 (PE 0, i.e., self on single-core)
    //   [40]    = IRM = 0 (use target list, not all-but-self)
    let val: u64 = ((intid as u64) & 0xF) << 24 | 1;
    core::arch::asm!(
        "msr ICC_SGI1_EL1, {}",
        "isb",
        in(reg) val,
    );
}
