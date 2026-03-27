# GICv3 Virtual Interrupt Injection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a sans-I/O GICv3 model that delivers virtual timer (PPI 27) and UART (SPI 33) interrupts to guest VMs via List Registers.

**Architecture:** A new `gic.rs` module provides `VirtualGic` with GICD + GICR register emulation and `sync_lrs()` for LR injection. The hypervisor calls `sync_lrs()` as a side-effect on every guest-resuming code path, writing pending interrupts into VCpuContext LR fields. A new `TrapEvent::TimerIrq` and `HypervisorAction::ResumeGuest` handle timer interrupt reporting. The DTS gains a GICv3 node so Linux can discover the interrupt controller.

**Tech Stack:** Rust (no_std), ARM GICv3 specification, Device Tree

**Spec:** `docs/specs/2026-03-27-gicv3-virtual-interrupt-design.md`

---

## File Structure

| File | Responsibility | Action |
|------|---------------|--------|
| `crates/harmony-hypervisor/src/gic.rs` | VirtualGic: GICD + GICR register state, MMIO read/write, LR injection | Create |
| `crates/harmony-hypervisor/src/lib.rs` | Crate module tree | Modify: add `pub mod gic;` |
| `crates/harmony-hypervisor/src/platform/mod.rs` | Platform constants | Modify: add GIC IPA + size constants |
| `crates/harmony-hypervisor/src/trap.rs` | Trap events and actions | Modify: add TimerIrq, ResumeGuest |
| `crates/harmony-hypervisor/src/vcpu.rs` | vCPU context and Vm struct | Modify: add GIC fields, gic to Vm |
| `crates/harmony-hypervisor/src/hypervisor.rs` | Hypervisor state machine | Modify: GIC MMIO dispatch, sync_lrs, TimerIrq |
| `crates/harmony-hypervisor/dts/guest-virt.dts` | Guest device tree | Modify: add GICv3 node, PL011 interrupts |
| `crates/harmony-hypervisor/blobs/guest-virt.dtb` | Compiled DTB | Rebuild from DTS |

---

### Task 1: Platform constants and trap type additions

**Files:**
- Modify: `crates/harmony-hypervisor/src/platform/mod.rs`
- Modify: `crates/harmony-hypervisor/src/trap.rs`

**Context:** We need GIC IPA constants for MMIO dispatch, and two new enum variants (`TrapEvent::TimerIrq` and `HypervisorAction::ResumeGuest`) that later tasks depend on.

- [ ] **Step 1: Add GIC constants to platform/mod.rs**

After the existing `GUEST_CNTVOFF_EL2` constant (line 30), add:

```rust
/// GIC Distributor virtual IPA (QEMU virt layout).
pub const GICD_IPA: u64 = 0x0800_0000;
/// GIC Distributor MMIO region size (64 KiB).
pub const GICD_SIZE: u64 = 0x1_0000;
/// GIC Redistributor virtual IPA (QEMU virt layout).
pub const GICR_IPA: u64 = 0x080A_0000;
/// GIC Redistributor MMIO region size (128 KiB: RD_base + SGI_base frames).
pub const GICR_SIZE: u64 = 0x2_0000;
/// Number of List Registers modeled (matches QEMU virt default).
pub const LR_COUNT: usize = 4;
```

- [ ] **Step 2: Add TimerIrq to TrapEvent**

In `crates/harmony-hypervisor/src/trap.rs`, add after the `SmcForward` variant (line 60), before the closing `}`:

```rust
    /// Virtual timer fired (CNTV_CTL_EL0.ISTATUS set and IMASK clear).
    /// Reported by the platform shim after every guest trap.
    TimerIrq,
```

- [ ] **Step 3: Add ResumeGuest to HypervisorAction**

In `trap.rs`, add after the `VirtioQueueNotify` variant (line 155), before the closing `}`:

```rust
    /// Resume guest execution. LRs are already synced in VCpuContext.
    /// The platform shim restores VCpuContext as-is and erets.
    ResumeGuest,
```

- [ ] **Step 4: Run tests to verify nothing broke**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Run: `cargo test -p harmony-hypervisor -- --nocapture`
Expected: ALL pass (no code uses the new variants yet, so no behavioral change)

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-hypervisor/src/platform/mod.rs crates/harmony-hypervisor/src/trap.rs
git commit -m "feat(hypervisor): add GIC platform constants, TimerIrq event, and ResumeGuest action"
```

---

### Task 2: VirtualGic — GICD register emulation

**Files:**
- Create: `crates/harmony-hypervisor/src/gic.rs`
- Modify: `crates/harmony-hypervisor/src/lib.rs` (add `pub mod gic;`)

**Context:** The VirtualGic struct holds all GIC state. This task implements the distributor (GICD) registers. The redistributor and LR injection are added in Tasks 3-4.

- [ ] **Step 1: Create gic.rs with struct and GICD constants**

Create `crates/harmony-hypervisor/src/gic.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! GICv3 virtual interrupt controller — distributor + redistributor model.
//!
//! Emulates enough of the ARM GICv3 for Linux to probe and route
//! timer (PPI 27) and UART (SPI 33) interrupts. No LPI, no ITS,
//! no multi-vCPU routing.

use crate::platform::LR_COUNT;

/// Number of IRQ lines modeled (ITLinesNumber=1 → 64 IRQs).
const IRQ_COUNT: usize = 64;

/// GICD register offsets.
mod gicd {
    pub const CTLR: u32 = 0x0000;
    pub const TYPER: u32 = 0x0004;
    pub const IIDR: u32 = 0x0008;
    pub const IGROUPR: u32 = 0x0080;
    pub const ISENABLER: u32 = 0x0100;
    pub const ICENABLER: u32 = 0x0180;
    pub const ISPENDR: u32 = 0x0200;
    pub const ICPENDR: u32 = 0x0280;
    pub const IPRIORITYR: u32 = 0x0400;
    pub const ITARGETSR: u32 = 0x0800;
    pub const ICFGR: u32 = 0x0C00;
    pub const PIDR2: u32 = 0xFFE8;
}

/// GIC region for MMIO dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GicRegion {
    Distributor,
    RedistributorRd,
    RedistributorSgi,
}

/// GICv3 virtual interrupt controller.
pub struct VirtualGic {
    // Distributor state
    ctlr: u32,
    group: [u32; 2],
    enable: [u32; 2],
    pending: [u32; 2],
    priority: [u8; IRQ_COUNT],
    config: [u32; 4],

    // Redistributor state
    waker: u32,
}

impl Default for VirtualGic {
    fn default() -> Self {
        Self {
            ctlr: 0,
            group: [0; 2],
            enable: [0; 2],
            pending: [0; 2],
            priority: [0; IRQ_COUNT],
            config: [0; 4],
            waker: 0,
        }
    }
}

impl VirtualGic {
    pub fn new() -> Self {
        Self::default()
    }
}
```

- [ ] **Step 2: Add GICD read method**

```rust
    /// Read a distributor register by offset.
    pub fn read_gicd(&self, offset: u32) -> u64 {
        match offset {
            gicd::CTLR => self.ctlr as u64,
            gicd::TYPER => {
                // ITLinesNumber=1 (64 IRQs), CPUNumber=0, SecurityExtn=0
                1u64
            }
            gicd::IIDR => 0x0100_0000, // Implementer: Harmony (arbitrary)
            o if (gicd::IGROUPR..gicd::IGROUPR + 8).contains(&o) => {
                let idx = ((o - gicd::IGROUPR) / 4) as usize;
                if idx < 2 { self.group[idx] as u64 } else { 0 }
            }
            o if (gicd::ISENABLER..gicd::ISENABLER + 8).contains(&o)
                || (gicd::ICENABLER..gicd::ICENABLER + 8).contains(&o) =>
            {
                let idx = ((o & 0x7) / 4) as usize;
                if idx < 2 { self.enable[idx] as u64 } else { 0 }
            }
            o if (gicd::ISPENDR..gicd::ISPENDR + 8).contains(&o)
                || (gicd::ICPENDR..gicd::ICPENDR + 8).contains(&o) =>
            {
                let idx = ((o & 0x7) / 4) as usize;
                if idx < 2 { self.pending[idx] as u64 } else { 0 }
            }
            o if (gicd::IPRIORITYR..gicd::IPRIORITYR + IRQ_COUNT as u32).contains(&o) => {
                // 4 priority bytes packed into one 32-bit read
                let base = (o - gicd::IPRIORITYR) as usize;
                let mut val = 0u64;
                for i in 0..4.min(IRQ_COUNT - base) {
                    val |= (self.priority[base + i] as u64) << (i * 8);
                }
                val
            }
            o if (gicd::ITARGETSR..gicd::ITARGETSR + 64).contains(&o) => {
                // Single vCPU: all targets are CPU 0 (0x01 per byte)
                0x0101_0101
            }
            o if (gicd::ICFGR..gicd::ICFGR + 16).contains(&o) => {
                let idx = ((o - gicd::ICFGR) / 4) as usize;
                if idx < 4 { self.config[idx] as u64 } else { 0 }
            }
            gicd::PIDR2 => 0x3B, // GICv3 arch revision (bits [7:4] = 0x3)
            _ => 0,
        }
    }
```

- [ ] **Step 3: Add GICD write method**

```rust
    /// Write a distributor register by offset.
    pub fn write_gicd(&mut self, offset: u32, value: u64) {
        let val32 = value as u32;
        match offset {
            gicd::CTLR => self.ctlr = val32,
            o if (gicd::IGROUPR..gicd::IGROUPR + 8).contains(&o) => {
                let idx = ((o - gicd::IGROUPR) / 4) as usize;
                if idx < 2 { self.group[idx] = val32; }
            }
            o if (gicd::ISENABLER..gicd::ISENABLER + 8).contains(&o) => {
                let idx = ((o - gicd::ISENABLER) / 4) as usize;
                if idx < 2 { self.enable[idx] |= val32; } // OR to set
            }
            o if (gicd::ICENABLER..gicd::ICENABLER + 8).contains(&o) => {
                let idx = ((o - gicd::ICENABLER) / 4) as usize;
                if idx < 2 { self.enable[idx] &= !val32; } // AND-NOT to clear
            }
            o if (gicd::ISPENDR..gicd::ISPENDR + 8).contains(&o) => {
                let idx = ((o - gicd::ISPENDR) / 4) as usize;
                if idx < 2 { self.pending[idx] |= val32; }
            }
            o if (gicd::ICPENDR..gicd::ICPENDR + 8).contains(&o) => {
                let idx = ((o - gicd::ICPENDR) / 4) as usize;
                if idx < 2 { self.pending[idx] &= !val32; }
            }
            o if (gicd::IPRIORITYR..gicd::IPRIORITYR + IRQ_COUNT as u32).contains(&o) => {
                let base = (o - gicd::IPRIORITYR) as usize;
                for i in 0..4.min(IRQ_COUNT - base) {
                    self.priority[base + i] = ((value >> (i * 8)) & 0xFF) as u8;
                }
            }
            o if (gicd::ICFGR..gicd::ICFGR + 16).contains(&o) => {
                let idx = ((o - gicd::ICFGR) / 4) as usize;
                if idx < 4 { self.config[idx] = val32; }
            }
            _ => {} // Unknown writes ignored
        }
    }
```

- [ ] **Step 4: Add GICD unit tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gicd_typer_returns_it_lines_number_1() {
        let gic = VirtualGic::new();
        assert_eq!(gic.read_gicd(gicd::TYPER), 1);
    }

    #[test]
    fn gicd_pidr2_returns_gicv3_revision() {
        let gic = VirtualGic::new();
        assert_eq!(gic.read_gicd(gicd::PIDR2) & 0xF0, 0x30);
    }

    #[test]
    fn gicd_isenabler_icenabler_set_clear() {
        let mut gic = VirtualGic::new();
        // Enable IRQ 33 (bit 1 of ISENABLER[1])
        gic.write_gicd(gicd::ISENABLER + 4, 1 << 1);
        assert_eq!(gic.read_gicd(gicd::ISENABLER + 4) & (1 << 1), 1 << 1);
        // Disable it
        gic.write_gicd(gicd::ICENABLER + 4, 1 << 1);
        assert_eq!(gic.read_gicd(gicd::ISENABLER + 4) & (1 << 1), 0);
    }

    #[test]
    fn gicd_ispendr_icpendr_set_clear() {
        let mut gic = VirtualGic::new();
        gic.write_gicd(gicd::ISPENDR, 1 << 27); // PPI 27
        assert_ne!(gic.read_gicd(gicd::ISPENDR) & (1 << 27), 0);
        gic.write_gicd(gicd::ICPENDR, 1 << 27);
        assert_eq!(gic.read_gicd(gicd::ISPENDR) & (1 << 27), 0);
    }

    #[test]
    fn gicd_priority_byte_access() {
        let mut gic = VirtualGic::new();
        // Write priority for IRQ 33 (byte offset 33 from IPRIORITYR base)
        // Aligned to 4-byte group: offset = 33 & !3 = 32, byte index = 33 - 32 = 1
        gic.write_gicd(gicd::IPRIORITYR + 32, 0xA0 << 8); // byte 1 = 0xA0
        assert_eq!(gic.priority[33], 0xA0);
    }

    #[test]
    fn gicd_itargetsr_returns_cpu0() {
        let gic = VirtualGic::new();
        assert_eq!(gic.read_gicd(gicd::ITARGETSR), 0x0101_0101);
    }

    #[test]
    fn gicd_unknown_register_reads_zero() {
        let gic = VirtualGic::new();
        assert_eq!(gic.read_gicd(0xF000), 0);
    }
}
```

- [ ] **Step 5: Add module to lib.rs**

In `crates/harmony-hypervisor/src/lib.rs`, add after line 6 (`pub mod platform;`):

```rust
pub mod gic;
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p harmony-hypervisor gic -- --nocapture`
Expected: ALL pass (7 tests)

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-hypervisor/src/gic.rs crates/harmony-hypervisor/src/lib.rs
git commit -m "feat(hypervisor): add VirtualGic with GICD register emulation"
```

---

### Task 3: GICR redistributor register emulation

**Files:**
- Modify: `crates/harmony-hypervisor/src/gic.rs`

**Context:** The redistributor handles per-CPU SGI/PPI state (IRQs 0-31). It has two 64 KiB frames: RD_base (control) and SGI_base (enable/pending/priority). SGI_base shares `enable[0]`, `pending[0]`, and `priority[0..31]` with the distributor.

- [ ] **Step 1: Add GICR constants and read/write methods**

Add GICR offset constants:

```rust
mod gicr {
    // RD_base frame (offset 0x0000-0xFFFF from GICR base)
    pub const CTLR: u32 = 0x0000;
    pub const IIDR: u32 = 0x0004;
    pub const TYPER_LO: u32 = 0x0008;
    pub const TYPER_HI: u32 = 0x000C;
    pub const WAKER: u32 = 0x0014;

    // SGI_base frame (offset 0x10000-0x1FFFF from GICR base)
    pub const SGI_ISENABLER0: u32 = 0x0100;
    pub const SGI_ICENABLER0: u32 = 0x0180;
    pub const SGI_ISPENDR0: u32 = 0x0200;
    pub const SGI_ICPENDR0: u32 = 0x0280;
    pub const SGI_IPRIORITYR: u32 = 0x0400;
}
```

Add methods to VirtualGic:

```rust
    /// Read a redistributor RD_base register (frame 0).
    pub fn read_gicr_rd(&self, offset: u32) -> u64 {
        match offset {
            gicr::CTLR => 0,
            gicr::IIDR => 0x0100_0000, // Implementer: Harmony
            gicr::TYPER_LO => {
                // Last=1 (bit 4), ProcessorNumber=0
                0x10
            }
            gicr::TYPER_HI => 0,
            gicr::WAKER => self.waker as u64,
            _ => 0,
        }
    }

    /// Write a redistributor RD_base register (frame 0).
    pub fn write_gicr_rd(&mut self, offset: u32, value: u64) {
        match offset {
            gicr::WAKER => self.waker = value as u32,
            _ => {}
        }
    }

    /// Read a redistributor SGI_base register (frame 1).
    /// Offset is relative to SGI_base (0x10000 already subtracted).
    pub fn read_gicr_sgi(&self, offset: u32) -> u64 {
        match offset {
            gicr::SGI_ISENABLER0 | gicr::SGI_ICENABLER0 => self.enable[0] as u64,
            gicr::SGI_ISPENDR0 | gicr::SGI_ICPENDR0 => self.pending[0] as u64,
            o if (gicr::SGI_IPRIORITYR..gicr::SGI_IPRIORITYR + 32).contains(&o) => {
                let base = (o - gicr::SGI_IPRIORITYR) as usize;
                let mut val = 0u64;
                for i in 0..4.min(32 - base) {
                    val |= (self.priority[base + i] as u64) << (i * 8);
                }
                val
            }
            _ => 0,
        }
    }

    /// Write a redistributor SGI_base register (frame 1).
    pub fn write_gicr_sgi(&mut self, offset: u32, value: u64) {
        let val32 = value as u32;
        match offset {
            gicr::SGI_ISENABLER0 => self.enable[0] |= val32,
            gicr::SGI_ICENABLER0 => self.enable[0] &= !val32,
            gicr::SGI_ISPENDR0 => self.pending[0] |= val32,
            gicr::SGI_ICPENDR0 => self.pending[0] &= !val32,
            o if (gicr::SGI_IPRIORITYR..gicr::SGI_IPRIORITYR + 32).contains(&o) => {
                let base = (o - gicr::SGI_IPRIORITYR) as usize;
                for i in 0..4.min(32 - base) {
                    self.priority[base + i] = ((value >> (i * 8)) & 0xFF) as u8;
                }
            }
            _ => {}
        }
    }
```

- [ ] **Step 2: Add GICR tests**

```rust
    #[test]
    fn gicr_typer_reports_last_cpu() {
        let gic = VirtualGic::new();
        assert_eq!(gic.read_gicr_rd(gicr::TYPER_LO) & 0x10, 0x10); // Last=1
        assert_eq!(gic.read_gicr_rd(gicr::TYPER_HI), 0);
    }

    #[test]
    fn gicr_waker_round_trip() {
        let mut gic = VirtualGic::new();
        gic.write_gicr_rd(gicr::WAKER, 0x02);
        assert_eq!(gic.read_gicr_rd(gicr::WAKER), 0x02);
    }

    #[test]
    fn gicr_sgi_enable_shared_with_gicd() {
        let mut gic = VirtualGic::new();
        // Enable PPI 27 via GICR SGI_base
        gic.write_gicr_sgi(gicr::SGI_ISENABLER0, 1 << 27);
        // Should be visible in GICD ISENABLER[0] too
        assert_ne!(gic.read_gicd(gicd::ISENABLER) & (1 << 27), 0);
        // Disable via GICR
        gic.write_gicr_sgi(gicr::SGI_ICENABLER0, 1 << 27);
        assert_eq!(gic.read_gicd(gicd::ISENABLER) & (1 << 27), 0);
    }

    #[test]
    fn gicr_sgi_pending_shared_with_gicd() {
        let mut gic = VirtualGic::new();
        gic.write_gicr_sgi(gicr::SGI_ISPENDR0, 1 << 27);
        assert_ne!(gic.read_gicd(gicd::ISPENDR) & (1 << 27), 0);
    }
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p harmony-hypervisor gic -- --nocapture`
Expected: ALL pass (7 GICD + 4 GICR = 11 tests)

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-hypervisor/src/gic.rs
git commit -m "feat(hypervisor): add GICR redistributor register emulation"
```

---

### Task 4: Interrupt injection — pend/unpend and sync_lrs

**Files:**
- Modify: `crates/harmony-hypervisor/src/gic.rs`
- Modify: `crates/harmony-hypervisor/src/vcpu.rs`

**Context:** This is the core injection mechanism. `pend()` sets a pending bit, `sync_lrs()` scans pending+enabled IRQs and writes the top-priority ones into VCpuContext List Registers.

- [ ] **Step 1: Add GIC fields to VCpuContext**

In `crates/harmony-hypervisor/src/vcpu.rs`, add after `cntv_cval_el0` (line 27):

```rust
    pub ich_lr: [u64; 4],        // GICv3 List Registers
    pub ich_hcr_el2: u64,        // GICv3 Hypervisor Control Register
    pub icc_pmr_el1: u64,        // Interrupt Priority Mask Register
    pub icc_sre_el1: u64,        // System Register Enable
```

Note: `VCpuContext` derives `Default`, so these will default to 0. The `LR_COUNT` constant is 4 — use a fixed `[u64; 4]` array.

- [ ] **Step 2: Add VirtualGic to Vm struct**

In `vcpu.rs`, add import:
```rust
use crate::gic::VirtualGic;
```

Add field to Vm (after `virtio_net`, line 43):
```rust
    pub gic: VirtualGic,
```

- [ ] **Step 3: Fix Vm construction in hypervisor.rs**

Add `gic: VirtualGic::new()` to the Vm construction in `hvc_vm_create` and add `vm.gic = VirtualGic::new();` to the cold-restart path in `hvc_vm_start` (alongside existing `vm.uart = VirtualUart::new()`).

Add import:
```rust
use crate::gic::VirtualGic;
```

- [ ] **Step 4: Add pend/unpend/is_pending/is_enabled helpers to VirtualGic**

In `gic.rs`:

```rust
    /// Set the pending bit for an IRQ.
    pub fn pend(&mut self, irq: u32) {
        if (irq as usize) < IRQ_COUNT {
            let idx = (irq / 32) as usize;
            self.pending[idx] |= 1 << (irq % 32);
        }
    }

    /// Clear the pending bit for an IRQ.
    pub fn unpend(&mut self, irq: u32) {
        if (irq as usize) < IRQ_COUNT {
            let idx = (irq / 32) as usize;
            self.pending[idx] &= !(1 << (irq % 32));
        }
    }

    /// Check if an IRQ is pending.
    pub fn is_pending(&self, irq: u32) -> bool {
        if (irq as usize) < IRQ_COUNT {
            let idx = (irq / 32) as usize;
            self.pending[idx] & (1 << (irq % 32)) != 0
        } else {
            false
        }
    }

    /// Check if an IRQ is enabled.
    pub fn is_enabled(&self, irq: u32) -> bool {
        if (irq as usize) < IRQ_COUNT {
            let idx = (irq / 32) as usize;
            self.enable[idx] & (1 << (irq % 32)) != 0
        } else {
            false
        }
    }
```

- [ ] **Step 5: Add sync_lrs method**

```rust
    /// Scan pending+enabled IRQs and populate List Registers in VCpuContext.
    /// Called by the hypervisor before every guest-resuming action.
    pub fn sync_lrs(&self, ich_lr: &mut [u64; 4], ich_hcr: &mut u64) {
        // Clear all LRs
        *ich_lr = [0u64; 4];

        // Collect pending+enabled IRQs with their priorities
        let mut candidates: [(u32, u8); IRQ_COUNT] = [(0, 0xFF); IRQ_COUNT];
        let mut count = 0;

        for irq in 0..IRQ_COUNT as u32 {
            let idx = (irq / 32) as usize;
            let bit = 1 << (irq % 32);
            if self.pending[idx] & bit != 0 && self.enable[idx] & bit != 0 {
                candidates[count] = (irq, self.priority[irq as usize]);
                count += 1;
            }
        }

        // Sort by priority (lower value = higher priority)
        // Simple insertion sort — at most 64 candidates
        for i in 1..count {
            let key = candidates[i];
            let mut j = i;
            while j > 0 && candidates[j - 1].1 > key.1 {
                candidates[j] = candidates[j - 1];
                j -= 1;
            }
            candidates[j] = key;
        }

        // Pack top LR_COUNT candidates into LR format
        let lr_count = count.min(LR_COUNT);
        for i in 0..lr_count {
            let (irq, prio) = candidates[i];
            // LR format: State=Pending(01) | Group=1 | Priority | vINTID
            ich_lr[i] = (0b01u64 << 62)      // State = pending
                | (1u64 << 60)                // Group = 1 (non-secure)
                | ((prio as u64) << 48)       // Priority
                | (irq as u64);              // vINTID
        }

        // Enable virtual interrupt delivery if any LR is populated
        if lr_count > 0 {
            *ich_hcr |= 1; // ICH_HCR_EL2.En = 1
        }
    }
```

- [ ] **Step 6: Add injection tests**

```rust
    #[test]
    fn pend_unpend_round_trip() {
        let mut gic = VirtualGic::new();
        gic.pend(27);
        assert!(gic.is_pending(27));
        gic.unpend(27);
        assert!(!gic.is_pending(27));
    }

    #[test]
    fn sync_lrs_populates_lr_for_pending_enabled_irq() {
        let mut gic = VirtualGic::new();
        gic.pend(27);
        gic.write_gicr_sgi(gicr::SGI_ISENABLER0, 1 << 27); // Enable PPI 27
        gic.priority[27] = 0xA0;

        let mut lr = [0u64; 4];
        let mut hcr = 0u64;
        gic.sync_lrs(&mut lr, &mut hcr);

        assert_ne!(lr[0], 0, "LR[0] should be populated");
        assert_eq!(lr[0] & 0xFFFF_FFFF, 27, "vINTID should be 27");
        assert_eq!((lr[0] >> 62) & 0x3, 0b01, "state should be pending");
        assert_eq!((lr[0] >> 48) & 0xFF, 0xA0, "priority should be 0xA0");
        assert_eq!(hcr & 1, 1, "ICH_HCR_EL2.En should be set");
    }

    #[test]
    fn sync_lrs_skips_disabled_irqs() {
        let mut gic = VirtualGic::new();
        gic.pend(27); // Pending but NOT enabled

        let mut lr = [0u64; 4];
        let mut hcr = 0u64;
        gic.sync_lrs(&mut lr, &mut hcr);

        assert_eq!(lr[0], 0, "disabled IRQ should not get an LR");
    }

    #[test]
    fn sync_lrs_respects_priority_ordering() {
        let mut gic = VirtualGic::new();
        // IRQ 33 (SPI, priority 0xC0 = low) and IRQ 27 (PPI, priority 0x40 = high)
        gic.pend(33);
        gic.write_gicd(gicd::ISENABLER + 4, 1 << 1); // Enable SPI 33
        gic.priority[33] = 0xC0;
        gic.pend(27);
        gic.write_gicr_sgi(gicr::SGI_ISENABLER0, 1 << 27); // Enable PPI 27
        gic.priority[27] = 0x40;

        let mut lr = [0u64; 4];
        let mut hcr = 0u64;
        gic.sync_lrs(&mut lr, &mut hcr);

        // LR[0] should be IRQ 27 (higher priority = lower value)
        assert_eq!(lr[0] & 0xFFFF_FFFF, 27);
        // LR[1] should be IRQ 33
        assert_eq!(lr[1] & 0xFFFF_FFFF, 33);
    }

    #[test]
    fn sync_lrs_caps_at_lr_count() {
        let mut gic = VirtualGic::new();
        // Pend and enable 6 IRQs
        for irq in 0..6u32 {
            gic.pend(irq);
            gic.enable[0] |= 1 << irq;
            gic.priority[irq as usize] = (irq as u8) * 0x10;
        }

        let mut lr = [0u64; 4];
        let mut hcr = 0u64;
        gic.sync_lrs(&mut lr, &mut hcr);

        // Only 4 LRs should be populated (LR_COUNT = 4)
        assert_ne!(lr[0], 0);
        assert_ne!(lr[1], 0);
        assert_ne!(lr[2], 0);
        assert_ne!(lr[3], 0);
        // Top 4 by priority should be IRQs 0,1,2,3 (lowest priority values)
        assert_eq!(lr[0] & 0xFFFF_FFFF, 0);
        assert_eq!(lr[3] & 0xFFFF_FFFF, 3);
    }
```

- [ ] **Step 7: Run tests**

Run: `cargo test -p harmony-hypervisor -- --nocapture`
Expected: ALL pass

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-hypervisor/src/gic.rs crates/harmony-hypervisor/src/vcpu.rs crates/harmony-hypervisor/src/hypervisor.rs
git commit -m "feat(hypervisor): add GIC interrupt injection via sync_lrs and pend/unpend"
```

---

### Task 5: Wire GIC into hypervisor MMIO dispatch

**Files:**
- Modify: `crates/harmony-hypervisor/src/hypervisor.rs`

**Context:** Add GICD and GICR MMIO range checks to `handle_data_abort`, wire `sync_lrs` into all guest-resuming code paths, and handle `TrapEvent::TimerIrq`.

- [ ] **Step 1: Add GIC imports and MMIO dispatch**

In `hypervisor.rs` imports (lines 9-12), add the GIC constants:
```rust
use crate::platform::{
    GICD_IPA, GICD_SIZE, GICR_IPA, GICR_SIZE,
    // ... existing constants ...
};
use crate::gic::GicRegion;
```

In `handle_data_abort`, add two new IPA range checks **before** the unknown-IPA kill (before line 357). Insert after the UART block (line 356):

```rust
    // GIC Distributor range
    if (GICD_IPA..GICD_IPA + GICD_SIZE).contains(&ipa) {
        let offset = (ipa - GICD_IPA) as u32;
        let vm = self.vms.get_mut(&vmid.0)
            .ok_or(HypervisorError::InvalidVmId(vmid.0 as u64))?;
        let read_value = match access {
            AccessType::Write { value } => { vm.gic.write_gicd(offset, value); 0 }
            AccessType::Read => vm.gic.read_gicd(offset),
        };
        vm.gic.sync_lrs(&mut vm.vcpu.ich_lr, &mut vm.vcpu.ich_hcr_el2);
        return Ok(HypervisorAction::MmioResult {
            emit: None, read_value, width, srt, pc_advance: 4,
        });
    }

    // GIC Redistributor range
    if (GICR_IPA..GICR_IPA + GICR_SIZE).contains(&ipa) {
        let offset = (ipa - GICR_IPA) as u32;
        let vm = self.vms.get_mut(&vmid.0)
            .ok_or(HypervisorError::InvalidVmId(vmid.0 as u64))?;
        let read_value = if offset < 0x10000 {
            // RD_base frame
            match access {
                AccessType::Write { value } => { vm.gic.write_gicr_rd(offset, value); 0 }
                AccessType::Read => vm.gic.read_gicr_rd(offset),
            }
        } else {
            // SGI_base frame
            let sgi_offset = offset - 0x10000;
            match access {
                AccessType::Write { value } => { vm.gic.write_gicr_sgi(sgi_offset, value); 0 }
                AccessType::Read => vm.gic.read_gicr_sgi(sgi_offset),
            }
        };
        vm.gic.sync_lrs(&mut vm.vcpu.ich_lr, &mut vm.vcpu.ich_hcr_el2);
        return Ok(HypervisorAction::MmioResult {
            emit: None, read_value, width, srt, pc_advance: 4,
        });
    }
```

- [ ] **Step 2: Add sync_lrs to existing guest-resuming paths**

For the **UART MmioResult** path (around line 349-355), add sync_lrs before the return:
```rust
        vm.gic.sync_lrs(&mut vm.vcpu.ich_lr, &mut vm.vcpu.ich_hcr_el2);
        return Ok(HypervisorAction::MmioResult { ... });
```

For the **VirtIO-net MmioResult** paths (around lines 313-334), add sync_lrs before each return. You need a mutable borrow of `vm` — it's already obtained at line 307-310.

For the **EnterGuest** path in `hvc_vm_start`, add before the `Ok(EnterGuest { ... })`:
```rust
        vm.gic.sync_lrs(&mut vm.vcpu.ich_lr, &mut vm.vcpu.ich_hcr_el2);
        // Also initialize ICC_SRE_EL1 for system register access
        vm.vcpu.icc_sre_el1 = 0x7; // SRE + DFB + DIB
```

For the **HvcResult** path from `HVC_PING` (if a guest VM is active), add sync_lrs. Check if `active_vmid` is Some and sync.

For **VirtioQueueNotify**, add sync_lrs before returning the action.

For **ForwardSmc** (PSCI calls — the shim advances PC and resumes guest after EL3 returns), add sync_lrs before returning. Access the active VM via `active_vmid` and sync if a guest is running.

- [ ] **Step 3: Add TimerIrq handler**

In the `handle()` method's match (around line 53-87), add a new arm:

```rust
        TrapEvent::TimerIrq => {
            let vmid = self.active_vmid.ok_or(HypervisorError::NoActiveVm)?;
            let vm = self.vms.get_mut(&vmid.0)
                .ok_or(HypervisorError::InvalidVmId(vmid.0 as u64))?;
            vm.gic.pend(27); // PPI 27 = virtual timer
            vm.gic.sync_lrs(&mut vm.vcpu.ich_lr, &mut vm.vcpu.ich_hcr_el2);
            Ok(HypervisorAction::ResumeGuest)
        }
```

- [ ] **Step 4: Add integration tests**

```rust
#[test]
fn timer_irq_pends_ppi_27() {
    let mut hyp = /* create test hypervisor */;
    let vmid = /* create and start VM */;

    // Enable PPI 27 via GICR SGI_base ISENABLER0
    let _ = hyp.handle(TrapEvent::DataAbort {
        ipa: GICR_IPA + 0x10000 + 0x0100, // SGI_base ISENABLER0
        access: AccessType::Write { value: 1 << 27 },
        width: 4, srt: 0,
    }, &mut test_alloc).unwrap();

    // Fire timer
    let action = hyp.handle(TrapEvent::TimerIrq, &mut test_alloc).unwrap();
    assert!(matches!(action, HypervisorAction::ResumeGuest));

    // Verify LR populated
    let vm = hyp.vm(vmid).unwrap();
    assert_ne!(vm.vcpu.ich_lr[0], 0);
    assert_eq!(vm.vcpu.ich_lr[0] & 0xFFFF_FFFF, 27);
}

#[test]
fn gicd_mmio_reads_typer_through_hypervisor() {
    let mut hyp = /* create test hypervisor */;
    let vmid = /* create and start VM */;

    let action = hyp.handle(TrapEvent::DataAbort {
        ipa: GICD_IPA + 0x0004, // GICD_TYPER
        access: AccessType::Read,
        width: 4, srt: 0,
    }, &mut test_alloc).unwrap();

    match action {
        HypervisorAction::MmioResult { read_value, .. } => {
            assert_eq!(read_value, 1); // ITLinesNumber=1
        }
        _ => panic!("expected MmioResult"),
    }
}
```

Adapt the test helpers to match the existing test infrastructure (follow patterns from existing `uart_probe_via_hypervisor` and `vm_start_sets_x0_to_dtb_ipa` tests).

- [ ] **Step 5: Run all tests**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Run: `cargo test -p harmony-hypervisor -- --nocapture`
Expected: ALL pass

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-hypervisor/src/hypervisor.rs
git commit -m "feat(hypervisor): wire GIC MMIO dispatch, sync_lrs, and TimerIrq handling"
```

---

### Task 6: DTS update — GICv3 node and PL011 interrupts

**Files:**
- Modify: `crates/harmony-hypervisor/dts/guest-virt.dts`
- Rebuild: `crates/harmony-hypervisor/blobs/guest-virt.dtb`

**Context:** Add the GICv3 interrupt controller node and wire PL011 UART interrupts so Linux discovers the GIC during boot.

- [ ] **Step 1: Update guest-virt.dts**

Replace the comment about missing GIC with the actual GIC node. Add before the `pl011@9000000` node:

```dts
	intc: interrupt-controller@8000000 {
		compatible = "arm,gic-v3";
		#interrupt-cells = <3>;
		interrupt-controller;
		reg = <0x0 0x08000000 0x0 0x10000>,
		      <0x0 0x080a0000 0x0 0x20000>;
	};
```

Update the PL011 node to add interrupts:
```dts
	pl011@9000000 {
		compatible = "arm,pl011", "arm,primecell";
		reg = <0x0 0x09000000 0x0 0x1000>;
		interrupts = <0 1 4>;
		interrupt-parent = <&intc>;
		clock-names = "uartclk", "apb_pclk";
		clocks = <&apb_pclk>, <&apb_pclk>;
	};
```

Remove the old comment about GIC being intentionally omitted.

- [ ] **Step 2: Recompile DTB**

```bash
dtc -I dts -O dtb -o crates/harmony-hypervisor/blobs/guest-virt.dtb crates/harmony-hypervisor/dts/guest-virt.dts
```

Verify: `dtc -I dtb -O dts crates/harmony-hypervisor/blobs/guest-virt.dtb > /dev/null`

- [ ] **Step 3: Run tests to ensure DTB embedding still works**

Run: `cargo test -p harmony-microkernel guest_loader -- --nocapture`
Expected: PASS (FDT magic test still passes with new DTB)

- [ ] **Step 4: Run full CI checks**

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Run: `rustup run nightly cargo fmt --all -- --check`
Run: `cargo test --workspace`

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-hypervisor/dts/guest-virt.dts crates/harmony-hypervisor/blobs/guest-virt.dtb
git commit -m "feat(hypervisor): add GICv3 node to guest DTS and wire PL011 interrupts"
```

---

## Verification Checklist

After all tasks are complete:

- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] `rustup run nightly cargo fmt --all -- --check` passes
- [ ] GICD registers: TYPER, PIDR2, ISENABLER/ICENABLER, ISPENDR/ICPENDR, IPRIORITYR, ITARGETSR (unit tests)
- [ ] GICR registers: TYPER lo/hi, WAKER, SGI_base enable/pending/priority (unit tests)
- [ ] GICR SGI_base shares state with GICD for IRQs 0-31 (unit test)
- [ ] pend/unpend/is_pending/is_enabled helpers (unit tests)
- [ ] sync_lrs populates LRs for pending+enabled IRQs by priority (unit tests)
- [ ] sync_lrs caps at 4 LRs (unit test)
- [ ] TimerIrq pends PPI 27 and returns ResumeGuest (integration test)
- [ ] GICD MMIO through hypervisor reads TYPER correctly (integration test)
- [ ] DTS has GICv3 node with correct register addresses
- [ ] PL011 node has interrupts property
- [ ] DTB compiles from updated DTS
