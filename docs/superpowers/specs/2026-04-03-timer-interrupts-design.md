# Scheduler Phase 1: Timer Interrupts

**Bead:** harmony-os-p8w (P2, feature)
**Date:** 2026-04-03
**Status:** Design approved

## Goal

Get a periodic 100 Hz tick interrupt firing on aarch64 QEMU virt. This is the hardware foundation for the preemptive scheduler — everything in Phases 2-6 builds on having a reliable tick with full context save/restore.

## Architecture

Three new/modified components:

1. **GICv3 driver** (`gic.rs`) — initializes distributor, redistributor, and CPU interface; provides ack/eoi
2. **Timer interrupt enable** (extend `timer.rs`) — arms the physical timer at 100 Hz, rearms on each tick
3. **IRQ handler** (extend `vectors.rs`) — full GP register save/restore, dispatches to Rust handler

The physical timer (CNTP_*) fires PPI 30 (INTID 30). The GICv3 routes it through the redistributor to the CPU interface. The IRQ exception vectors invoke `el1_irq_handler`, which saves full context (same TrapFrame as the existing sync handler), calls a Rust dispatch function, restores context, and returns via `eret`.

## Scope

**In scope:**
- GICv3 initialization (GICD, GICR, ICC system registers)
- Physical timer interrupt enable (CNTP_CTL_EL0, CNTP_TVAL_EL0)
- IRQ handler assembly with full GP register save/restore (272-byte TrapFrame)
- Atomic tick counter readable via `timer::tick_count()`
- Platform constants for GIC addresses + MMU device-memory mapping
- FDT parser extension to extract redistributor base address (infrastructure correctness)
- Serial verification output (tick count every 100 ticks = once per second)

**Out of scope:**
- FP/SIMD register save (Phase 2 — lazy save on context switch)
- Context switching / scheduler logic (Phase 2-3)
- x86_64 PIT/LAPIC variant (separate follow-up bead)
- Multiple interrupt sources (future — only timer PPI for now)
- GICv2 / Apple AIC support (separate beads)

## GICv3 Driver

New file: `crates/harmony-boot-aarch64/src/gic.rs`

### Initialization Sequence

**1. Distributor (GICD) — MMIO at `gicd_base`:**
- Write GICD_CTLR: set ARE_NS (bit 4) and EnableGrp1NS (bit 1)
- Poll GICD_CTLR.RWP (bit 31) until clear (register write pending)
- Distributor configuration is minimal because the timer is a PPI (per-processor), not an SPI

**2. Redistributor (GICR) — MMIO at `gicr_base`:**
- Wake up: clear ProcessorSleep (bit 1) in GICR_WAKER, poll until ChildrenAsleep (bit 2) clears
- In SGI_base frame (GICR base + 0x10000):
  - Set INTID 30 to Group 1 NS: set bit 30 in GICR_IGROUPR0
  - Set priority 0 (highest) for INTID 30: write 0 to GICR_IPRIORITYR byte 30
  - Enable INTID 30: set bit 30 in GICR_ISENABLER0

**3. CPU Interface (ICC) — system registers:**
- ICC_PMR_EL1 = 0xFF (allow all priorities)
- ICC_IGRPEN1_EL1 = 1 (enable Group 1 interrupts)
- ISB to ensure register writes take effect

### Public API

- `unsafe fn init(gicd_base: *mut u8, gicr_base: *mut u8)` — full initialization. Safety: must be called once at EL1, before unmasking IRQs.
- `fn ack() -> u32` — read ICC_IAR1_EL1, returns INTID (0-1023) or 1023 for spurious
- `fn eoi(intid: u32)` — write ICC_EOIR1_EL1 to signal end-of-interrupt

### GIC Register Map (Phase 1 subset)

| Register | Offset/Name | Access | Purpose |
|----------|-------------|--------|---------|
| GICD_CTLR | GICD+0x0000 | MMIO R/W | Distributor control (ARE_NS, EnableGrp1NS) |
| GICR_WAKER | GICR+0x0014 | MMIO R/W | Redistributor wake control |
| GICR_IGROUPR0 | GICR+0x10080 | MMIO R/W | PPI group assignment (Group 0 vs Group 1) |
| GICR_ISENABLER0 | GICR+0x10100 | MMIO W | PPI enable (write-1-to-set) |
| GICR_IPRIORITYR | GICR+0x10400 | MMIO R/W | PPI priority (byte per INTID) |
| ICC_IAR1_EL1 | system reg | MRS | Interrupt acknowledge (returns INTID) |
| ICC_EOIR1_EL1 | system reg | MSR | End of interrupt |
| ICC_PMR_EL1 | system reg | MSR | Priority mask (0xFF = all allowed) |
| ICC_IGRPEN1_EL1 | system reg | MSR | Group 1 interrupt enable |

## Timer Interrupt Enable

Extend `crates/harmony-boot-aarch64/src/timer.rs`.

### New State

- `TICK_COUNT: AtomicU64` — incremented on each IRQ, read via `tick_count()`
- `RELOAD_VALUE: AtomicU32` — cached reload value for rearm (`freq / hz`)

### New Functions

**`pub fn enable_tick(hz: u32)`**
- Computes reload: `freq() / hz as u64` (e.g., 62.5 MHz / 100 = 625,000)
- Stores reload value in `RELOAD_VALUE`
- Writes CNTP_TVAL_EL0 = reload value (starts countdown)
- Writes CNTP_CTL_EL0 = 0x1 (ENABLE=1, IMASK=0)

**`pub fn rearm()`**
- Writes CNTP_TVAL_EL0 = stored reload value
- Called by IRQ handler after each tick. Writing TVAL resets countdown from *now*, so any IRQ handler latency doesn't accumulate across ticks.

**`pub fn on_tick()`**
- Increments `TICK_COUNT` (Relaxed ordering — single core, no cross-CPU visibility needed)
- Calls `rearm()`

**`pub fn tick_count() -> u64`**
- Returns current tick count (Relaxed load)

### Timer Registers

| Register | Purpose |
|----------|---------|
| CNTP_TVAL_EL0 | Countdown timer value. Fires interrupt when reaches 0. |
| CNTP_CTL_EL0 | Control: bit 0 = ENABLE, bit 1 = IMASK (0 = interrupt enabled), bit 2 = ISTATUS (read-only) |
| CNTPCT_EL0 | Physical counter (already used by `counter()`) |
| CNTFRQ_EL0 | Counter frequency (already used by `freq()`) |

## IRQ Handler

Modify `crates/harmony-boot-aarch64/src/vectors.rs`.

### Vector Table Changes

Two entries change from `b unexpected_exception` to `b el1_irq_handler`:
- Offset 0x280: Current EL, SPx, IRQ — fires when IRQ arrives during kernel execution
- Offset 0x480: Lower EL, AArch64, IRQ — fires when IRQ arrives during user-mode execution (wired now for Phase 2, unused in Phase 1)

### `el1_irq_handler` Assembly

Identical structure to existing `el1_sync_handler`:
1. `sub sp, sp, #272` — allocate TrapFrame
2. Save x0-x30 via `stp` pairs (same layout as sync handler)
3. Save ELR_EL1 and SPSR_EL1 to TrapFrame
4. `bl irq_dispatch` — call Rust handler
5. Restore ELR_EL1 and SPSR_EL1
6. Restore x0-x30 via `ldp` pairs
7. `add sp, sp, #272` — deallocate TrapFrame
8. `eret`

The TrapFrame layout is identical to the sync handler's. This is deliberate: Phase 2's context switch will swap TrapFrame pointers, and it works regardless of whether the preempted context was in an SVC or an IRQ.

### `irq_dispatch()` Rust Function

Lives in `vectors.rs` alongside the assembly that calls it (via `bl irq_dispatch`). This mirrors how the sync handler assembly calls `svc_handler` and `abort_handler`, though those live in `syscall.rs` because they have more complex dispatch logic. `irq_dispatch` is simple glue — 10 lines of ack/match/eoi.

```rust
#[no_mangle]
extern "C" fn irq_dispatch() {
    let intid = gic::ack();
    match intid {
        30 => timer::on_tick(),      // Physical timer PPI
        1023 => {}                   // Spurious interrupt — no EOI needed
        id => {
            // Unknown interrupt — log and EOI to prevent hang
            serial_println!("IRQ: unexpected INTID {}", id);
        }
    }
    if intid != 1023 {
        gic::eoi(intid);
    }
}
```

Spurious interrupts (INTID 1023) must not receive an EOI — writing 1023 to ICC_EOIR1_EL1 is architecturally UNPREDICTABLE.

## Platform Constants & MMU Mapping

Modify `crates/harmony-boot-aarch64/src/platform.rs`.

The codebase uses compile-time constants for hardware addresses (e.g., `PL011_BASE`), not runtime FDT discovery. The GIC follows this pattern.

### New Constants (QEMU virt)

```rust
#[cfg(feature = "qemu-virt")]
pub const GICD_BASE: usize = 0x0800_0000;  // GICv3 Distributor

#[cfg(feature = "qemu-virt")]
pub const GICR_BASE: usize = 0x080A_0000;  // GICv3 Redistributor
```

### MMIO_REGIONS Update

The GIC distributor and redistributor must be mapped as Device memory (NO_CACHE) by the MMU, or volatile reads/writes will hit stale cache lines. Add to the QEMU virt `MMIO_REGIONS` array:

```rust
#[cfg(feature = "qemu-virt")]
pub const MMIO_REGIONS: &[(usize, usize)] = &[
    (PL011_BASE, 1),       // existing
    (GICD_BASE, 16),       // GICv3 Distributor (64 KiB)
    (GICR_BASE, 256),      // GICv3 Redistributor (1 MiB — covers all CPU frames)
];
```

The redistributor region is large because GICv3 allocates 128 KiB per CPU (RD_base + SGI_base frames). On QEMU virt with up to 8 vCPUs, this is up to 1 MiB. Mapping the full region is safe — unused pages are simply never accessed.

### RPi5 (deferred)

RPi5 uses Apple AIC, not GICv3. GIC constants are `#[cfg(feature = "qemu-virt")]` only. RPi5 interrupt support is tracked by harmony-os-1hc.

## FDT Parser Extension

Modify `crates/harmony-boot-aarch64/src/fdt_parse.rs` and `crates/harmony-microkernel/src/hardware_config.rs`.

While the boot path uses platform constants, the FDT parser should also correctly extract redistributor addresses for completeness and future dynamic discovery.

### HardwareConfig Change

Add redistributor fields to `InterruptControllerConfig`:

```rust
pub struct InterruptControllerConfig {
    pub base: u64,                          // GICD base (existing)
    pub size: u64,                          // GICD size (existing)
    pub variant: InterruptControllerVariant, // existing
    pub redistributor_base: Option<u64>,    // NEW — GICR base (GICv3 only)
    pub redistributor_size: Option<u64>,    // NEW — GICR size (GICv3 only)
}
```

### FDT Parser Change

For `arm,gic-v3` nodes, read the second `reg` entry (redistributor) in addition to the first (distributor):

```rust
"arm,gic-v3" => {
    let mut regs = node.reg().unwrap();
    let gicd = regs.next();
    let gicr = regs.next();  // Second reg = redistributor
    if let Some(gicd_reg) = gicd {
        config.interrupt_controller = Some(InterruptControllerConfig {
            base: gicd_reg.starting_address as u64,
            size: gicd_reg.size.unwrap_or(0x10000) as u64,
            variant: InterruptControllerVariant::GicV3,
            redistributor_base: gicr.map(|r| r.starting_address as u64),
            redistributor_size: gicr.map(|r| r.size.unwrap_or(0xF60000) as u64),
        });
    }
}
```

All other construction sites (GICv2, AIC, test parser in `hardware_config.rs`) set `redistributor_base: None, redistributor_size: None`.

## Boot Integration

Modify `crates/harmony-boot-aarch64/src/main.rs`.

### Initialization Order

After `vectors::init()` (line 449) and before the ELF test binary execution:

```
vectors::init()                                          // existing
gic::init(GICD_BASE as *mut u8, GICR_BASE as *mut u8)  // NEW — enable GICv3 + PPI 30
timer::enable_tick(100)                                  // NEW — arm physical timer at 100 Hz
asm!("msr daifclr, #2")                                 // NEW — unmask IRQ exceptions
```

Enabling interrupts before the ELF test run means the tick fires during both the test binary and the event loop. This is correct behavior — in Phase 2+, we need interrupts during user code. Phase 1 proves it doesn't break anything.

### DAIF Unmasking

`msr daifclr, #2` clears the I (IRQ mask) bit in DAIF, allowing IRQ exceptions. This is the "point of no return" — from here on, `el1_irq_handler` can fire at any instruction boundary.

The D (debug), A (SError), and F (FIQ) bits are left unchanged. FIQ is unused. SError handling is a separate concern.

### Event Loop

No changes. The loop already uses `wfe` (Wait For Event) at the bottom, which suspends the CPU until a hardware event — including the timer interrupt. This means the event loop naturally wakes on each tick without polling.

## Verification

**Serial output during boot:**
```
[Vectors] Exception vector table installed
[GIC] GICv3 initialized: GICD=0x8000000 GICR=0x80A0000
[Timer] 100 Hz tick armed (reload=625000)
```

**Periodic serial output (once per second):**
```
[Tick] 100
[Tick] 200
[Tick] 300
```

This confirms: interrupts are firing, the handler runs without crashing, and the counter increments at the expected rate (100 ticks/second).

**Failure modes are loud:**
- Wrong register save/restore → data abort or corrupted execution (immediate crash)
- Missing EOI → GIC suppresses further interrupts (tick count stops incrementing)
- Wrong INTID routing → `unexpected INTID` message in serial log
- Timer not rearmed → single tick then silence

## Testing

**Host-runnable unit tests:**
- Reload value computation: `freq / hz` for various timer frequencies
- `counter_to_ms` arithmetic (already tested, unchanged)
- Tick counter increment logic

**QEMU integration test (primary verification):**
- `cargo xtask qemu-test` boots the aarch64 unikernel on QEMU virt
- Verify boot output includes GIC/timer initialization messages
- Verify tick count appears in serial output
- Verify existing ELF test binary still passes (interrupts don't break Linuxulator)

No new integration test harness needed — the existing QEMU boot test covers the full path.

## Files Changed

| File | Changes |
|------|---------|
| `crates/harmony-boot-aarch64/src/gic.rs` | **New** — GICv3 driver (init, ack, eoi) |
| `crates/harmony-boot-aarch64/src/timer.rs` | Add `enable_tick()`, `rearm()`, `on_tick()`, `tick_count()` |
| `crates/harmony-boot-aarch64/src/vectors.rs` | Add `el1_irq_handler` assembly + `irq_dispatch()` Rust function, wire 0x280 and 0x480 vector entries |
| `crates/harmony-boot-aarch64/src/platform.rs` | Add `GICD_BASE`, `GICR_BASE` constants; extend `MMIO_REGIONS` with GIC pages |
| `crates/harmony-boot-aarch64/src/fdt_parse.rs` | Extract GICv3 redistributor base from second FDT reg entry |
| `crates/harmony-microkernel/src/hardware_config.rs` | Add `redistributor_base`/`redistributor_size` to `InterruptControllerConfig` |
| `crates/harmony-boot-aarch64/src/main.rs` | Add `mod gic`, GIC init, timer arm, DAIF unmask after vectors::init() |

## Out of Scope

- FP/SIMD save/restore — Phase 2 (lazy save on context switch)
- Context switching — Phase 2 (harmony-os-n9r)
- Round-robin scheduling — Phase 3 (harmony-os-5eb)
- x86_64 PIT/LAPIC — separate follow-up bead
- Tick-less idle (dynamic tick reprogramming) — future optimization
- Nested interrupts — not needed on single-core with one interrupt source
