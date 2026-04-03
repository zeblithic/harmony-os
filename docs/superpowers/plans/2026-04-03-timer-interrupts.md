# Timer Interrupts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Get a periodic 100 Hz tick interrupt firing on aarch64 QEMU virt, with full GP register save/restore in the IRQ handler.

**Architecture:** Add GICv3 driver (`gic.rs`) for interrupt controller initialization and ack/eoi. Extend `timer.rs` with interrupt enable and rearm. Add `el1_irq_handler` assembly to `vectors.rs` mirroring the existing sync handler's TrapFrame layout. Wire into boot sequence after `vectors::init()`.

**Tech Stack:** Rust (no_std), ARM Generic Timer (CNTP_*), GICv3 (ICC system registers + GICD/GICR MMIO), aarch64 assembly (`global_asm!`).

**Spec:** `docs/superpowers/specs/2026-04-03-timer-interrupts-design.md`

---

## File Structure

| File | Responsibility | Changes |
|------|---------------|---------|
| `crates/harmony-microkernel/src/hardware_config.rs` | Hardware platform descriptor types | Add `redistributor_base`/`redistributor_size` fields to `InterruptControllerConfig` |
| `crates/harmony-boot-aarch64/src/fdt_parse.rs` | FDT → HardwareConfig conversion | Extract second GICv3 `reg` entry (redistributor) |
| `crates/harmony-boot-aarch64/src/platform.rs` | Compile-time hardware constants | Add `GICD_BASE`, `GICR_BASE`; extend `MMIO_REGIONS` |
| `crates/harmony-boot-aarch64/src/gic.rs` | **New** — GICv3 driver | `init()`, `ack()`, `eoi()` |
| `crates/harmony-boot-aarch64/src/timer.rs` | ARM Generic Timer | Add `enable_tick()`, `rearm()`, `on_tick()`, `tick_count()` |
| `crates/harmony-boot-aarch64/src/vectors.rs` | Exception vector table | Add `el1_irq_handler` assembly + `irq_dispatch()` Rust function |
| `crates/harmony-boot-aarch64/src/main.rs` | Boot entry point | Add `mod gic`, GIC init, timer arm, DAIF unmask |

---

### Task 1: Extend `InterruptControllerConfig` with redistributor fields

**Files:**
- Modify: `crates/harmony-microkernel/src/hardware_config.rs:46-52`

**Context:** `InterruptControllerConfig` currently has `base`, `size`, and `variant`. GICv3 has a separate redistributor (GICR) region that isn't captured. We add optional fields for it. All existing construction sites must add the new fields.

- [ ] **Step 1: Write a failing test for the new fields**

Add to the existing `tests` module at the bottom of `crates/harmony-microkernel/src/hardware_config.rs`:

```rust
    #[test]
    fn gicv3_redistributor_fields() {
        let config = InterruptControllerConfig {
            base: 0x0800_0000,
            size: 0x1_0000,
            variant: InterruptControllerVariant::GicV3,
            redistributor_base: Some(0x080A_0000),
            redistributor_size: Some(0xF6_0000),
        };
        assert_eq!(config.redistributor_base, Some(0x080A_0000));
        assert_eq!(config.redistributor_size, Some(0xF6_0000));
    }

    #[test]
    fn gicv2_redistributor_fields_are_none() {
        let config = InterruptControllerConfig {
            base: 0x0800_0000,
            size: 0x1_0000,
            variant: InterruptControllerVariant::GicV2,
            redistributor_base: None,
            redistributor_size: None,
        };
        assert_eq!(config.redistributor_base, None);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p harmony-microkernel -- hardware_config::tests::gicv3_redistributor 2>&1 | tail -5`
Expected: compilation error — `InterruptControllerConfig` has no field `redistributor_base`.

- [ ] **Step 3: Add the new fields to `InterruptControllerConfig`**

In `crates/harmony-microkernel/src/hardware_config.rs`, replace the struct definition at lines 47-52:

```rust
/// MMIO-mapped interrupt controller.
#[derive(Debug, Clone)]
pub struct InterruptControllerConfig {
    pub base: u64,
    pub size: u64,
    pub variant: InterruptControllerVariant,
    /// GICv3 redistributor base address. `None` for GICv2/AIC.
    pub redistributor_base: Option<u64>,
    /// GICv3 redistributor region size in bytes. `None` for GICv2/AIC.
    pub redistributor_size: Option<u64>,
}
```

- [ ] **Step 4: Fix all existing construction sites**

There are 5 places that construct `InterruptControllerConfig`. Add `redistributor_base: None, redistributor_size: None` to each GICv2/AIC site, and `redistributor_base: Some(...)` for GICv3 sites where the data is available.

**`crates/harmony-microkernel/src/hardware_config.rs` — test helper `parse_fdt_for_test` (line ~162):**

The GICv3 branch currently reads only the first reg entry. Update to also read the second:

```rust
                        "arm,gic-v3" => {
                            if let Some(mut regs) = node.reg() {
                                if let Some(gicd_reg) = regs.next() {
                                    let gicr_reg = regs.next();
                                    config.interrupt_controller =
                                        Some(InterruptControllerConfig {
                                            base: gicd_reg.starting_address as u64,
                                            size: gicd_reg.size.unwrap_or(0x10000) as u64,
                                            variant: InterruptControllerVariant::GicV3,
                                            redistributor_base: gicr_reg
                                                .map(|r| r.starting_address as u64),
                                            redistributor_size: gicr_reg
                                                .map(|r| r.size.unwrap_or(0xF60000) as u64),
                                        });
                                }
                            }
                        }
```

The GICv2 branch (line ~171):

```rust
                        "arm,cortex-a15-gic" | "arm,gic-400" => {
                            if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                                config.interrupt_controller = Some(InterruptControllerConfig {
                                    base: reg.starting_address as u64,
                                    size: reg.size.unwrap_or(0x10000) as u64,
                                    variant: InterruptControllerVariant::GicV2,
                                    redistributor_base: None,
                                    redistributor_size: None,
                                });
                            }
                        }
```

**`crates/harmony-boot-aarch64/src/fdt_parse.rs` — 3 construction sites (lines 67-84):**

GICv3 (line 67):
```rust
                "arm,gic-v3" => {
                    if let Some(mut regs) = node.reg() {
                        if let Some(gicd_reg) = regs.next() {
                            let gicr_reg = regs.next();
                            config.interrupt_controller = Some(InterruptControllerConfig {
                                base: gicd_reg.starting_address as u64,
                                size: gicd_reg.size.unwrap_or(0x10000) as u64,
                                variant: InterruptControllerVariant::GicV3,
                                redistributor_base: gicr_reg
                                    .map(|r| r.starting_address as u64),
                                redistributor_size: gicr_reg
                                    .map(|r| r.size.unwrap_or(0xF60000) as u64),
                            });
                        }
                    }
                }
```

GICv2 (line 76):
```rust
                "arm,cortex-a15-gic" | "arm,gic-400" => {
                    if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                        config.interrupt_controller = Some(InterruptControllerConfig {
                            base: reg.starting_address as u64,
                            size: reg.size.unwrap_or(0x10000) as u64,
                            variant: InterruptControllerVariant::GicV2,
                            redistributor_base: None,
                            redistributor_size: None,
                        });
                    }
                }
```

Apple AIC (line 85):
```rust
                "apple,aic" | "apple,aic2" => {
                    if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                        config.interrupt_controller = Some(InterruptControllerConfig {
                            base: reg.starting_address as u64,
                            size: reg.size.unwrap_or(0xC000) as u64,
                            variant: InterruptControllerVariant::AppleAic,
                            redistributor_base: None,
                            redistributor_size: None,
                        });
                    }
                }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel -- hardware_config::tests`
Expected: all 7 tests pass (5 existing + 2 new).

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-microkernel/src/hardware_config.rs crates/harmony-boot-aarch64/src/fdt_parse.rs
git commit -m "feat(hardware_config): add GICv3 redistributor fields to InterruptControllerConfig"
```

---

### Task 2: Add GIC platform constants and MMIO regions

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/platform.rs:14-59`

**Context:** The boot crate uses compile-time constants for hardware addresses (e.g., `PL011_BASE = 0x0900_0000`). The GIC follows this pattern. The `MMIO_REGIONS` array tells the MMU which address ranges to map as Device memory (NO_CACHE) — without this, volatile reads/writes to GIC registers would hit stale cache lines.

- [ ] **Step 1: Add GICD_BASE and GICR_BASE constants**

In `crates/harmony-boot-aarch64/src/platform.rs`, add after the `PL011_BASE` constant (after line 15):

```rust
/// GICv3 Distributor base address (QEMU virt).
#[cfg(feature = "qemu-virt")]
pub const GICD_BASE: usize = 0x0800_0000;

/// GICv3 Redistributor base address (QEMU virt).
#[cfg(feature = "qemu-virt")]
pub const GICR_BASE: usize = 0x080A_0000;
```

- [ ] **Step 2: Extend MMIO_REGIONS to include GIC pages**

Replace the QEMU virt `MMIO_REGIONS` definition (lines 56-59):

```rust
#[cfg(feature = "qemu-virt")]
pub const MMIO_REGIONS: &[(usize, usize)] = &[
    (PL011_BASE, 1),   // PL011 UART (4 KiB)
    (GICD_BASE, 16),   // GICv3 Distributor (64 KiB)
    (GICR_BASE, 256),  // GICv3 Redistributor (1 MiB — 128 KiB per CPU × 8 max)
];
```

- [ ] **Step 3: Add tests for the new constants**

Add to the existing `tests` module at the bottom of `platform.rs`:

```rust
    #[test]
    fn gic_bases_are_set() {
        #[cfg(feature = "qemu-virt")]
        {
            assert_ne!(GICD_BASE, 0);
            assert_ne!(GICR_BASE, 0);
            // GICR must be after GICD (separate MMIO region)
            assert!(GICR_BASE > GICD_BASE);
        }
    }

    #[test]
    fn mmio_regions_include_gic() {
        #[cfg(feature = "qemu-virt")]
        {
            let has_gicd = MMIO_REGIONS.iter().any(|&(base, _)| base == GICD_BASE);
            let has_gicr = MMIO_REGIONS.iter().any(|&(base, _)| base == GICR_BASE);
            assert!(has_gicd, "MMIO_REGIONS must include GICD");
            assert!(has_gicr, "MMIO_REGIONS must include GICR");
        }
    }
```

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-boot-aarch64/src/platform.rs
git commit -m "feat(platform): add GICv3 base addresses and MMIO regions for QEMU virt"
```

---

### Task 3: Create GICv3 driver

**Files:**
- Create: `crates/harmony-boot-aarch64/src/gic.rs`

**Context:** The GICv3 has three components: Distributor (GICD, MMIO), Redistributor (GICR, MMIO), and CPU Interface (ICC, system registers). We need to initialize all three and provide `ack()`/`eoi()` for the IRQ handler. The only interrupt source in Phase 1 is the physical timer (PPI 30, INTID 30).

GICD and GICR registers are accessed via volatile MMIO reads/writes. ICC registers are accessed via `msr`/`mrs` assembly instructions. All MMIO reads/writes use `core::ptr::read_volatile`/`write_volatile` because the GIC is a DMA-like device — the compiler must not optimize away or reorder these accesses.

- [ ] **Step 1: Create the GIC driver**

Create `crates/harmony-boot-aarch64/src/gic.rs`:

```rust
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
const TIMER_INTID: u32 = 30;

/// Spurious interrupt — returned by `ack()` when no valid interrupt is pending.
pub const SPURIOUS: u32 = 1023;

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
    while read_volatile(ctlr) & GICD_CTLR_RWP != 0 {
        core::hint::spin_loop();
    }

    // ── 2. Redistributor ────────────────────────────────────────────────
    // Wake the redistributor.
    let waker = gicr_base.add(GICR_WAKER) as *mut u32;
    let w = read_volatile(waker);
    write_volatile(waker, w & !GICR_WAKER_PROCESSOR_SLEEP);
    while read_volatile(waker) & GICR_WAKER_CHILDREN_ASLEEP != 0 {
        core::hint::spin_loop();
    }

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
```

- [ ] **Step 2: Register the module in `main.rs`**

In `crates/harmony-boot-aarch64/src/main.rs`, add `mod gic;` after line 16 (`mod timer;`):

```rust
mod gic;
```

- [ ] **Step 3: Verify compilation**

Run: `cd crates/harmony-boot-aarch64 && cargo +nightly check 2>&1 | tail -5`
Expected: compiles without errors. (We can't run unit tests on this crate — see Task 1 note — but `cargo check` validates the code.)

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-boot-aarch64/src/gic.rs crates/harmony-boot-aarch64/src/main.rs
git commit -m "feat(gic): add GICv3 driver for timer interrupt routing"
```

---

### Task 4: Add timer interrupt functions

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/timer.rs:24-62`

**Context:** The timer module currently reads the counter (`CNTPCT_EL0`) and frequency (`CNTFRQ_EL0`) but doesn't set up interrupts. We add `enable_tick()` to arm the physical timer, `rearm()` to reload the countdown after each tick, `on_tick()` as the IRQ handler callback, and `tick_count()` to read the monotonic tick counter.

The physical timer fires PPI 30 when its countdown register (`CNTP_TVAL_EL0`) reaches zero. The control register (`CNTP_CTL_EL0`) has bit 0 = ENABLE and bit 1 = IMASK (set IMASK=0 to allow interrupts).

- [ ] **Step 1: Write tests for the new timer functions**

Add to the existing `tests` module at the bottom of `crates/harmony-boot-aarch64/src/timer.rs`:

```rust
    #[test]
    fn reload_value_100hz_at_62_5_mhz() {
        // 62,500,000 Hz / 100 Hz = 625,000 ticks per interval
        let freq: u64 = 62_500_000;
        let hz: u32 = 100;
        let reload = (freq / hz as u64) as u32;
        assert_eq!(reload, 625_000);
    }

    #[test]
    fn reload_value_100hz_at_54_mhz() {
        // QEMU virt often reports 54 MHz
        let freq: u64 = 54_000_000;
        let hz: u32 = 100;
        let reload = (freq / hz as u64) as u32;
        assert_eq!(reload, 540_000);
    }

    #[test]
    fn reload_value_fits_u32() {
        // Even at 1 GHz / 100 Hz = 10,000,000 — fits in u32
        let freq: u64 = 1_000_000_000;
        let hz: u32 = 100;
        let reload = freq / hz as u64;
        assert!(reload <= u32::MAX as u64);
    }
```

- [ ] **Step 2: Add the new state and functions**

In `crates/harmony-boot-aarch64/src/timer.rs`, add the new statics after the existing `TIMER_FREQ` static (after line 29), and the new functions after `now_ms()` (after line 62):

Add statics (after line 29):

```rust
/// Monotonic tick counter — incremented by the IRQ handler on each timer tick.
#[cfg(target_arch = "aarch64")]
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Cached reload value for `rearm()` — set by `enable_tick()`.
#[cfg(target_arch = "aarch64")]
static RELOAD_VALUE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
```

Add the import for `AtomicU32` — update the existing import line at line 25:

```rust
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
```

Add functions after `now_ms()` (after line 62):

```rust
/// Arm the physical timer to fire periodic interrupts at `hz` Hz.
///
/// Computes the reload value from the cached timer frequency, writes
/// `CNTP_TVAL_EL0` (countdown), and enables the timer with interrupts
/// unmasked via `CNTP_CTL_EL0`.
///
/// # Panics
///
/// Panics if `hz` is 0 or if `init()` has not been called.
#[cfg(target_arch = "aarch64")]
pub fn enable_tick(hz: u32) {
    assert!(hz > 0, "tick frequency must be > 0");
    let f = freq();
    assert!(f > 0, "timer::init() must be called before enable_tick()");
    let reload = (f / hz as u64) as u32;
    RELOAD_VALUE.store(reload, Ordering::Relaxed);
    unsafe {
        // Load countdown register — fires interrupt when it reaches 0.
        core::arch::asm!("msr cntp_tval_el0, {}", in(reg) reload as u64);
        // Enable timer, unmask interrupt (ENABLE=1, IMASK=0).
        core::arch::asm!("msr cntp_ctl_el0, {}", in(reg) 1_u64);
    }
}

/// Reload the countdown timer for the next tick.
///
/// Called by the IRQ handler after each tick. Writes `CNTP_TVAL_EL0`
/// with the cached reload value, restarting the countdown from *now*.
#[cfg(target_arch = "aarch64")]
pub fn rearm() {
    let reload = RELOAD_VALUE.load(Ordering::Relaxed);
    unsafe {
        core::arch::asm!("msr cntp_tval_el0, {}", in(reg) reload as u64);
    }
}

/// Timer tick callback — called by the IRQ handler on each timer interrupt.
///
/// Increments the tick counter and rearms the timer for the next interval.
#[cfg(target_arch = "aarch64")]
pub fn on_tick() {
    TICK_COUNT.fetch_add(1, Ordering::Relaxed);
    rearm();
}

/// Return the number of timer ticks since interrupts were enabled.
#[cfg(target_arch = "aarch64")]
pub fn tick_count() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed)
}
```

- [ ] **Step 3: Verify compilation**

Run: `cd crates/harmony-boot-aarch64 && cargo +nightly check 2>&1 | tail -5`
Expected: compiles without errors.

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-boot-aarch64/src/timer.rs
git commit -m "feat(timer): add enable_tick/rearm/on_tick for periodic timer interrupts"
```

---

### Task 5: Add IRQ handler assembly and Rust dispatch

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/vectors.rs:51-205`

**Context:** The exception vector table has 16 entries, each 128 bytes. The IRQ entries at offset 0x280 (Current EL, SPx) and 0x480 (Lower EL, AArch64) currently branch to `unexpected_exception`. We replace them with `b el1_irq_handler`.

The `el1_irq_handler` assembly mirrors the existing `el1_sync_handler` exactly: same 272-byte TrapFrame allocation, same register save/restore sequence. This is deliberate — Phase 2's context switch needs identical layouts regardless of exception type.

The Rust `irq_dispatch()` function is called from the assembly via `bl irq_dispatch`. It acknowledges the interrupt via `gic::ack()`, handles INTID 30 (timer) by calling `timer::on_tick()`, and signals end-of-interrupt via `gic::eoi()`.

- [ ] **Step 1: Wire the IRQ vector entries**

In `crates/harmony-boot-aarch64/src/vectors.rs`, replace the two vector table entries:

At line 78-79 (offset 0x280 — Current EL, SPx, IRQ):
```rust
    // 0x280 — Current EL, SPx, IRQ (timer interrupt)
    "b el1_irq_handler",
```

At line 95-96 (offset 0x480 — Lower EL, AArch64, IRQ):
```rust
    // 0x480 — Lower EL, AArch64, IRQ (timer interrupt from user mode)
    "b el1_irq_handler",
```

- [ ] **Step 2: Add `el1_irq_handler` assembly**

Add the IRQ handler assembly after the existing `call_abort_handler` block (after line 204, before the closing `);` of the `global_asm!` invocation):

```rust
    // ── Out-of-line IRQ handler ──────────────────────────────────────
    // Saves the full TrapFrame (identical layout to el1_sync_handler)
    // so Phase 2 can context-switch from IRQ as easily as from SVC.

    "el1_irq_handler:",

    // Allocate TrapFrame (264 bytes, padded to 272 for 16-byte alignment)
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

    // Call Rust IRQ dispatch
    "bl irq_dispatch",

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
```

- [ ] **Step 3: Add the `irq_dispatch()` Rust function**

Add after the `global_asm!` invocation (after the closing `);` at the end of `vectors.rs`):

```rust
use crate::gic;
use crate::timer;

/// IRQ dispatch — called from `el1_irq_handler` assembly.
///
/// Acknowledges the interrupt via GIC, routes to the appropriate handler,
/// and signals end-of-interrupt. Spurious interrupts (INTID 1023) are
/// silently ignored — writing 1023 to ICC_EOIR1_EL1 is UNPREDICTABLE.
#[cfg(target_arch = "aarch64")]
#[no_mangle]
extern "C" fn irq_dispatch() {
    let intid = gic::ack();
    match intid {
        30 => timer::on_tick(),
        gic::SPURIOUS => {}
        _ => {
            // Unexpected interrupt — EOI it to prevent the GIC from
            // suppressing further interrupts, but otherwise ignore.
        }
    }
    if intid != gic::SPURIOUS {
        gic::eoi(intid);
    }
}
```

- [ ] **Step 4: Verify compilation**

Run: `cd crates/harmony-boot-aarch64 && cargo +nightly check 2>&1 | tail -5`
Expected: compiles without errors.

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-boot-aarch64/src/vectors.rs
git commit -m "feat(vectors): add el1_irq_handler with full TrapFrame save/restore and irq_dispatch"
```

---

### Task 6: Wire GIC + timer into boot sequence

**Files:**
- Modify: `crates/harmony-boot-aarch64/src/main.rs:446-451`

**Context:** The boot sequence currently initializes vectors at line 449, then immediately proceeds to load the ELF test binary. We insert GIC initialization, timer arming, and DAIF unmasking between `vectors::init()` and the ELF test.

The initialization order matters: GIC must be ready before the timer is armed, and both must be complete before IRQs are unmasked. If we unmask first, the pending timer interrupt hits an uninitialized GIC → `unexpected_exception`.

- [ ] **Step 1: Add GIC init, timer arm, and DAIF unmask**

In `crates/harmony-boot-aarch64/src/main.rs`, after the existing `vectors::init()` block (after line 450, the `[Vectors]` writeln), insert:

```rust
    // ── Initialize GICv3 interrupt controller ──
    unsafe { gic::init(platform::GICD_BASE as *mut u8, platform::GICR_BASE as *mut u8) };
    let _ = writeln!(
        serial,
        "[GIC] GICv3 initialized: GICD={:#x} GICR={:#x}",
        platform::GICD_BASE,
        platform::GICR_BASE,
    );

    // ── Arm the physical timer at 100 Hz ──
    timer::enable_tick(100);
    let _ = writeln!(
        serial,
        "[Timer] 100 Hz tick armed (reload={})",
        timer::freq() / 100,
    );

    // ── Unmask IRQ exceptions ──
    // From this point forward, el1_irq_handler fires on every timer tick.
    unsafe { core::arch::asm!("msr daifclr, #2") };
    let _ = writeln!(serial, "[IRQ] Interrupts unmasked");
```

- [ ] **Step 2: Add periodic tick logging to `on_tick`**

For verification, modify `timer::on_tick()` in `crates/harmony-boot-aarch64/src/timer.rs` to print the tick count once per second (every 100 ticks). Since we don't have a serial writer in the IRQ context, use `pl011::write_byte` directly:

Replace the `on_tick()` function body:

```rust
#[cfg(target_arch = "aarch64")]
pub fn on_tick() {
    let count = TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    rearm();

    // Print tick count once per second (every 100 ticks) for verification.
    if count % 100 == 0 {
        print_tick(count);
    }
}

/// Minimal serial print for IRQ context — no allocator, no formatting.
/// Writes "[Tick] NNNNN\r\n" via PL011.
#[cfg(target_arch = "aarch64")]
fn print_tick(count: u64) {
    use crate::pl011;

    let prefix = b"[Tick] ";
    for &b in prefix {
        unsafe { pl011::write_byte(b) };
    }

    // Convert count to decimal digits.
    let mut buf = [0u8; 20]; // u64 max is 20 digits
    let mut n = count;
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    for &b in &buf[i..] {
        unsafe { pl011::write_byte(b) };
    }
    unsafe {
        pl011::write_byte(b'\r');
        pl011::write_byte(b'\n');
    }
}
```

- [ ] **Step 3: Verify compilation**

Run: `cd crates/harmony-boot-aarch64 && cargo +nightly check 2>&1 | tail -5`
Expected: compiles without errors.

- [ ] **Step 4: Run clippy**

Run: `cd crates/harmony-boot-aarch64 && cargo +nightly clippy -- -D warnings 2>&1 | tail -10`
Expected: no warnings.

- [ ] **Step 5: Run nightly rustfmt**

Run: `cargo +nightly fmt --all -- --check`
Expected: no formatting issues. If there are, run `cargo +nightly fmt --all` to fix.

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-boot-aarch64/src/main.rs crates/harmony-boot-aarch64/src/timer.rs
git commit -m "feat(boot): wire GIC + timer interrupts into aarch64 boot sequence"
```

---

### Task 7: QEMU integration test

**Files:**
- No file changes — verification only

**Context:** The primary verification for this feature is booting on QEMU virt and observing serial output. The existing `cargo xtask qemu-test` builds the aarch64 UEFI binary and boots it on QEMU. We verify that:
1. GIC and timer initialization messages appear
2. Tick count prints once per second
3. The existing ELF test binary still passes (interrupts don't break the Linuxulator)

- [ ] **Step 1: Build the aarch64 UEFI binary**

Run: `cd crates/harmony-boot-aarch64 && cargo +nightly build 2>&1 | tail -5`
Expected: builds successfully.

- [ ] **Step 2: Run QEMU integration test**

Run: `cargo xtask qemu-test 2>&1 | tail -30`
Expected output includes:
```
[Vectors] Exception vector table installed
[GIC] GICv3 initialized: GICD=0x8000000 GICR=0x80a0000
[Timer] 100 Hz tick armed (reload=...)
[IRQ] Interrupts unmasked
```
And periodic:
```
[Tick] 100
[Tick] 200
```
And the ELF test binary still passes (exit code 0).

- [ ] **Step 3: Verify no regressions**

Run: `cargo test --workspace 2>&1 | tail -10`
Expected: all workspace tests pass. The `harmony-microkernel` tests (including the new `gicv3_redistributor_fields` test) should all pass.

- [ ] **Step 4: Final commit (if any formatting fixes needed)**

If Steps 1-3 required any fixes, commit them:
```bash
git add -A
git commit -m "fix: address QEMU integration test findings"
```
