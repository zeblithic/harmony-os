# GICv3 Virtual Interrupt Injection for Guest VMs — Design Spec

## Goal

Add a sans-I/O GICv3 distributor/redistributor model that enables virtual
interrupt delivery to guest VMs via List Registers. The immediate targets
are the virtual timer (PPI 27) and PL011 UART (SPI 33), allowing the
Alpine Linux guest to boot past early init into timer-driven scheduling.

## Background

The EL2 hypervisor (harmony-os-ohp) boots Alpine Linux to earlycon output
but hangs when the kernel needs timer tick interrupts. Without a GIC, the
CPU can't deliver pending interrupts to the guest. GICv3 uses List
Registers (`ICH_LR<n>_EL2`) to inject virtual interrupts — the hardware
handles acknowledgment (IAR) and end-of-interrupt (EOIR) automatically.

The hypervisor already traps MMIO accesses via Stage-2 data aborts and
delegates to per-VM device structs (VirtualUart, VirtioNetDevice). This
design follows the same pattern for the GIC.

## Design Decisions

- **Timer + UART scope**: Model enough GICv3 for PPI 27 and SPI 33. No
  LPI, no ITS, no multi-vCPU routing.
- **Single module**: GICD + GICR in one `gic.rs` file/struct. With a
  single vCPU they share interrupt state — splitting adds cross-struct
  complexity for no benefit.
- **4 List Registers**: Matches QEMU virt default. Sufficient for 2
  active interrupts (timer + UART) with 2 spare. Reported via
  `ICH_VTR_EL2.ListRegs = 3` (0-indexed).
- **LRs in VCpuContext**: List Registers are per-vCPU state,
  saved/restored by the platform shim alongside GPRs and system
  registers. The hypervisor modifies them via `sync_lrs()` before guest
  entry.
- **No ICC register trapping**: GICv3 hardware handles IAR/EOIR via List
  Registers automatically. `ICC_SRE_EL1` set at VM start, `ICC_PMR_EL1`
  saved/restored. `ICH_HCR_EL2.En` enables virtual delivery.
- **QEMU virt addresses**: GICD at `0x0800_0000`, GICR at `0x080A_0000`.
  Already defined in `platform/qemu_virt.rs`.
- **64 IRQ lines**: `GICD_TYPER.ITLinesNumber = 1` → IRQs 0-63. Covers
  SGIs (0-15), PPIs (16-31), SPIs (32-63).

## VirtualGic Struct

```rust
pub struct VirtualGic {
    // Distributor state
    ctlr: u32,                // GICD_CTLR: enable groups
    group: [u32; 2],          // IGROUPR: group per IRQ (64 bits)
    enable: [u32; 2],         // ISENABLER/ICENABLER: enable per IRQ
    pending: [u32; 2],        // ISPENDR/ICPENDR: pending per IRQ
    priority: [u8; 64],       // IPRIORITYR: 8-bit priority per IRQ
    config: [u32; 4],         // ICFGR: 2-bit config per IRQ

    // Redistributor state
    waker: u32,               // GICR_WAKER: processor sleep control
}
```

~128 bytes per VM. No heap allocation.

## Distributor Registers (GICD)

MMIO region: `0x0800_0000` – `0x0800_FFFF` (64 KiB).

| Offset | Register | Read | Write |
|--------|----------|------|-------|
| 0x0000 | GICD_CTLR | Stored | Store |
| 0x0004 | GICD_TYPER | ITLinesNumber=1, CPUNumber=0 | — |
| 0x0008 | GICD_IIDR | Implementer ID (Harmony) | — |
| 0x0080 | GICD_IGROUPR[0..1] | Stored | Store |
| 0x0100 | GICD_ISENABLER[0..1] | Current enable bits | OR into enable |
| 0x0180 | GICD_ICENABLER[0..1] | Current enable bits | AND-NOT from enable |
| 0x0200 | GICD_ISPENDR[0..1] | Current pending bits | OR into pending |
| 0x0280 | GICD_ICPENDR[0..1] | Current pending bits | AND-NOT from pending |
| 0x0400 | GICD_IPRIORITYR[0..15] | Priority bytes | Store bytes |
| 0x0800 | GICD_ITARGETSR[0..15] | 0x01 (CPU 0) | Ignored (single vCPU) |
| 0x0C00 | GICD_ICFGR[0..3] | Stored | Store |
| 0xFFE8 | GICD_PIDR2 | 0x3B (GICv3 arch revision) | — |
| Other PIDR/CIDR | ID registers | GICv3 identification | — |

Registers beyond the 64-IRQ range (offset ≥ array bounds) read as 0,
writes ignored.

## Redistributor Registers (GICR)

MMIO region: `0x080A_0000` – `0x080B_FFFF` (128 KiB: 2 × 64 KiB frames).

**Frame 0 — RD_base** (offset `0x0000`–`0xFFFF`):

| Offset | Register | Read | Write |
|--------|----------|------|-------|
| 0x0000 | GICR_CTLR | 0 | Ignored |
| 0x0004 | GICR_IIDR | Implementer ID | — |
| 0x0008 | GICR_TYPER (lo32) | Last=1 (bit 4), ProcNum=0 | — |
| 0x000C | GICR_TYPER (hi32) | 0 (upper half) | — |
| 0x0014 | GICR_WAKER | Stored | Store |

**Frame 1 — SGI_base** (offset `0x10000`–`0x1FFFF`):

| Offset | Register | Read | Write |
|--------|----------|------|-------|
| 0x0100 | GICR_ISENABLER0 | enable[0] | OR into enable[0] |
| 0x0180 | GICR_ICENABLER0 | enable[0] | AND-NOT from enable[0] |
| 0x0200 | GICR_ISPENDR0 | pending[0] | OR into pending[0] |
| 0x0280 | GICR_ICPENDR0 | pending[0] | AND-NOT from pending[0] |
| 0x0400 | GICR_IPRIORITYR[0..7] | priority[0..31] | Store bytes |

GICR SGI_base shares `enable[0]`, `pending[0]`, and `priority[0..31]`
with the distributor — SGIs and PPIs (IRQs 0-31) are per-CPU and managed
through the redistributor.

## MMIO Dispatch

In `handle_data_abort`, add two new IPA range checks (before the
unknown-IPA kill):

```
GICD: 0x0800_0000 .. 0x0801_0000  → gic.read/write(Distributor, offset)
GICR: 0x080A_0000 .. 0x080C_0000  → gic.read/write(Redistributor*, offset)
```

GICR offset determines frame: `< 0x10000` → RedistributorRd, `>=
0x10000` → RedistributorSgi (subtract `0x10000` for SGI-frame-relative
offset).

```rust
pub enum GicRegion {
    Distributor,
    RedistributorRd,
    RedistributorSgi,
}
```

Returns `MmioResult { emit: None, read_value, width, srt, pc_advance: 4 }`
for all GIC accesses.

## Virtual Interrupt Injection

### List Register Format (64-bit)

| Bits | Field | Value |
|------|-------|-------|
| 63:62 | State | 01=pending |
| 60 | Group | 1 (Group 1, non-secure) |
| 55:48 | Priority | From IPRIORITYR[irq] |
| 31:0 | vINTID | IRQ number |

### Injection Flow

The key principle: `sync_lrs` runs as a **side-effect inside `handle()`**
on every code path that resumes the guest. It mutates `vcpu.ich_lr`
before the action is returned. The platform shim is "dumb" — it always
restores whatever is in VCpuContext, including LRs, without knowing
whether they changed.

1. **Interrupt source pends an IRQ:**
   - Timer: platform shim reports `TrapEvent::TimerIrq` → hypervisor
     calls `gic.pend(27)`.
   - UART: when UART TX completes and IMSC has TX bit unmasked, hypervisor
     calls `gic.pend(33)`.

2. **`handle()` calls `sync_lrs` before returning any guest-resuming
   action.** Every code path that returns `MmioResult`, `HvcResult`,
   `EnterGuest`, or `VirtioQueueNotify` calls `gic.sync_lrs(&mut vcpu)`
   as the last step before
   building the return value. This scans `pending & enable` bits, picks
   the top 4 by priority, packs into LR format, and writes to
   `vcpu.ich_lr[0..3]`. Non-resuming actions (`HaltGuest`, `DestroyVm`,
   `GuestExited`) skip `sync_lrs`.

3. **Platform shim restores LRs:** On guest entry, the shim writes
   `ICH_LR0_EL2` through `ICH_LR3_EL2` from VCpuContext, sets
   `ICH_HCR_EL2 = vcpu.ich_hcr_el2`, then `eret`. The shim does not
   need to know anything about the GIC model — it just restores state.

4. **Hardware delivers interrupt:** CPU checks LRs, signals virtual IRQ
   to guest. Guest reads `ICC_IAR1_EL1` — hardware returns vINTID from
   the highest-priority pending LR, transitions LR state to active.

5. **Guest EOIs:** Guest writes `ICC_EOIR1_EL1` — hardware clears LR.

6. **On next trap:** Platform shim saves LRs back to VCpuContext. The
   hypervisor can inspect them to see which interrupts were handled.

### sync_lrs Method

```rust
pub fn sync_lrs(&self, vcpu: &mut VCpuContext) {
    // Clear all LRs
    vcpu.ich_lr = [0u64; 4];

    // Collect pending+enabled IRQs, sorted by priority
    // Pack into LRs (max 4)
    // Set ICH_HCR_EL2.En = 1
}
```

### pend / unpend Methods

```rust
pub fn pend(&mut self, irq: u32)    // Set pending bit
pub fn unpend(&mut self, irq: u32)  // Clear pending bit
pub fn is_pending(&self, irq: u32) -> bool
pub fn is_enabled(&self, irq: u32) -> bool
```

## VCpuContext Additions

```rust
pub ich_lr: [u64; 4],        // List Registers (saved/restored by shim)
pub ich_hcr_el2: u64,        // Hypervisor Control Register
pub icc_pmr_el1: u64,        // Priority Mask Register
pub icc_sre_el1: u64,        // System Register Enable
```

At VM start, `icc_sre_el1` is initialized to `0x7` (SRE + DFB + DIB) to
enable system register access. `ich_hcr_el2` is set to `0x1` (En) by
`sync_lrs` to enable virtual interrupt delivery.

## TrapEvent Addition

```rust
TrapEvent::TimerIrq,  // Virtual timer fired (CNTV_CTL_EL0.ISTATUS)
```

**Platform shim behavior:** After every guest trap, the shim saves
VCpuContext, calls `handle(original_trap_event)`, processes the returned
action, then checks `CNTV_CTL_EL0`. If ISTATUS is set and IMASK is
clear, the shim calls `handle(TrapEvent::TimerIrq)` as a second call
before re-entering the guest.

**`handle(TimerIrq)` behavior:** The hypervisor calls `gic.pend(27)`,
then calls `sync_lrs(&mut vcpu)` (which picks up the now-pending timer
IRQ), and returns `HypervisorAction::ResumeGuest`. The shim treats
`ResumeGuest` the same as any guest-resuming action: restore VCpuContext
(including the updated LRs) and `eret`.

**New action variant:**

```rust
HypervisorAction::ResumeGuest,  // Continue guest execution (LRs already synced)
```

This is distinct from `EnterGuest` (which carries stage2_root and timer
config for initial entry). `ResumeGuest` carries no payload — the shim
just restores VCpuContext as-is and `eret`s.

## DTS Update

Add GICv3 node and wire PL011 interrupts in `guest-virt.dts`:

```dts
intc: interrupt-controller@8000000 {
    compatible = "arm,gic-v3";
    #interrupt-cells = <3>;
    interrupt-controller;
    reg = <0x0 0x08000000 0x0 0x10000>,
          <0x0 0x080a0000 0x0 0x20000>;
};
```

Update PL011 node:
```dts
pl011@9000000 {
    ...
    interrupts = <0 1 4>;
    interrupt-parent = <&intc>;
};
```

The `interrupts` property uses GIC 3-cell format: `<type irq_offset
flags>`. Type 0 = SPI, irq_offset 1 = SPI 33 (base 32 + offset 1),
flags 4 = level-high.

## New Files

- `crates/harmony-hypervisor/src/gic.rs` — VirtualGic struct and
  register emulation (~400 lines)

## Modified Files

- `crates/harmony-hypervisor/src/lib.rs` — add `pub mod gic;`
- `crates/harmony-hypervisor/src/vcpu.rs` — add GIC fields to
  VCpuContext, add `gic: VirtualGic` to Vm (also reset on cold restart)
- `crates/harmony-hypervisor/src/hypervisor.rs` — GICD/GICR MMIO
  dispatch, TimerIrq handling, sync_lrs before EnterGuest
- `crates/harmony-hypervisor/src/trap.rs` — add TrapEvent::TimerIrq
- `crates/harmony-hypervisor/src/platform/mod.rs` — add GIC size
  constants
- `crates/harmony-hypervisor/dts/guest-virt.dts` — add GICv3 node,
  wire PL011 interrupts

## Testing

### Unit tests (gic.rs)

- GICD_TYPER returns ITLinesNumber=1, CPUNumber=0
- GICD_PIDR2 returns GICv3 arch revision
- ISENABLER/ICENABLER set/clear semantics (OR / AND-NOT)
- ISPENDR/ICPENDR set/clear semantics
- Priority register byte read/write
- GICR_TYPER reports Last=1
- GICR_WAKER round-trip
- GICR SGI_base enable/pending (shared state with GICD for IRQs 0-31)
- Unknown register reads return 0
- PIDR/CIDR return GICv3 identification

### LR injection tests (gic.rs)

- sync_lrs populates LR for pending+enabled IRQ
- sync_lrs skips disabled IRQs
- sync_lrs respects priority ordering
- sync_lrs caps at 4 LRs
- pend/unpend/is_pending/is_enabled helpers

### Integration tests (hypervisor.rs)

- TimerIrq pends IRQ 27 in GIC
- GIC MMIO through hypervisor: DataAbort at GICD IPA reads TYPER
- Full sequence: enable IRQ 27 → TimerIrq → sync_lrs → verify LR in
  VCpuContext

## Out of Scope

- LPI (Locality-specific Peripheral Interrupts)
- ITS (Interrupt Translation Service)
- Multi-vCPU affinity routing (GICD_IROUTER)
- SGI generation (ICC_SGI1R_EL1)
- Interrupt preemption / nesting
- GIC maintenance interrupts (ICH_MISR_EL2)
- Priority drop / running priority tracking
- Full GICv3 model (>64 IRQs, security extensions)
