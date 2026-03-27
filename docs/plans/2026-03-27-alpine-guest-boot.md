# Alpine Linux Guest Boot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Boot an Alpine Linux kernel inside the EL2 micro-VM hypervisor to the point where earlycon prints boot messages on the virtual UART.

**Architecture:** Expand the virtual PL011 UART from a 2-register stub to a ~12-register emulator in a new `uart.rs` module. Add a guest loader module in the microkernel that embeds kernel/initramfs/DTB blobs and orchestrates VM boot via the existing HVC interface. Extend VM_START to pass the DTB address to the guest in x0 per the ARM64 boot protocol.

**Tech Stack:** Rust (no_std), ARM64 AArch64 (EL2 hypervisor), Device Tree (DTS/DTB)

**Spec:** `docs/specs/2026-03-27-alpine-guest-boot-design.md`

---

## File Structure

| File | Responsibility | Action |
|------|---------------|--------|
| `crates/harmony-hypervisor/src/uart.rs` | PL011 virtual UART register emulation | Create |
| `crates/harmony-hypervisor/src/hypervisor.rs` | Hypervisor state machine | Modify: delegate UART to VirtualUart, add uart to Vm |
| `crates/harmony-hypervisor/src/vcpu.rs` | vCPU context and Vm struct | Modify: add VirtualUart field to Vm |
| `crates/harmony-hypervisor/src/trap.rs` | Trap types and HVC IDs | Modify: document x3 for dtb_ipa in VM_START |
| `crates/harmony-hypervisor/src/lib.rs` | Crate module tree | Modify: add `pub mod uart;` |
| `crates/harmony-hypervisor/dts/guest-virt.dts` | Guest device tree source | Create |
| `crates/harmony-hypervisor/blobs/guest-virt.dtb` | Compiled DTB | Create (from dtc) |
| `crates/harmony-microkernel/src/guest_loader.rs` | Guest boot orchestration | Create |
| `crates/harmony-microkernel/src/lib.rs` | Microkernel module tree | Modify: add guest_loader mod |

---

### Task 1: VirtualUart — PL011 register emulation

**Files:**
- Create: `crates/harmony-hypervisor/src/uart.rs`
- Modify: `crates/harmony-hypervisor/src/lib.rs` (add `pub mod uart;`)

**Context:** The existing UART MMIO handling lives inline in `hypervisor.rs` handle_data_abort (lines 265-303). We're extracting and expanding it into a standalone module. The hypervisor currently returns `HypervisorAction::MmioResult { emit, read_value, width, srt, pc_advance }` — the VirtualUart will produce `(Option<u8>, u64)` (emit char, read value) and the hypervisor wraps it into MmioResult.

- [ ] **Step 1: Write failing tests for VirtualUart**

Create `crates/harmony-hypervisor/src/uart.rs` with tests:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! PL011 virtual UART register emulation.
//!
//! Emulates enough of the ARM PL011 for Linux earlycon and driver probe.
//! No interrupt support — UARTIMSC reads as 0, writes are ignored.

/// PL011 register offsets.
pub mod reg {
    pub const UARTDR: u16 = 0x000;
    pub const UARTFR: u16 = 0x018;
    pub const UARTIBRD: u16 = 0x024;
    pub const UARTFBRD: u16 = 0x028;
    pub const UARTLCR_H: u16 = 0x02C;
    pub const UARTCR: u16 = 0x030;
    pub const UARTIMSC: u16 = 0x038;
    pub const UARTICR: u16 = 0x044;
    pub const PERIPHID0: u16 = 0xFE0;
    pub const PERIPHID1: u16 = 0xFE4;
    pub const PERIPHID2: u16 = 0xFE8;
    pub const PERIPHID3: u16 = 0xFEC;
}

/// UARTFR flags: TX FIFO empty | RX FIFO empty.
const UARTFR_TXFE_RXFE: u64 = (1 << 7) | (1 << 4);

/// PL011 peripheral ID (rev r1p5): 0x00341011.
const PERIPHID: [u64; 4] = [0x11, 0x10, 0x34, 0x00];

pub struct VirtualUart {
    ibrd: u16,
    fbrd: u8,
    lcr_h: u8,
    cr: u16,
}

impl VirtualUart {
    pub fn new() -> Self {
        Self {
            ibrd: 0,
            fbrd: 0,
            lcr_h: 0,
            cr: 0x0300, // PL011 reset default: TXE | RXE enabled
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uartdr_write_emits_character() {
        let mut uart = VirtualUart::new();
        let emit = uart.write(reg::UARTDR, 0x41); // 'A'
        assert_eq!(emit, Some(0x41));
    }

    #[test]
    fn uartdr_read_returns_zero() {
        let uart = VirtualUart::new();
        assert_eq!(uart.read(reg::UARTDR), 0);
    }

    #[test]
    fn uartfr_returns_txfe_rxfe() {
        let uart = VirtualUart::new();
        assert_eq!(uart.read(reg::UARTFR), UARTFR_TXFE_RXFE);
    }

    #[test]
    fn periph_id_returns_pl011_id() {
        let uart = VirtualUart::new();
        assert_eq!(uart.read(reg::PERIPHID0), 0x11);
        assert_eq!(uart.read(reg::PERIPHID1), 0x10);
        assert_eq!(uart.read(reg::PERIPHID2), 0x34);
        assert_eq!(uart.read(reg::PERIPHID3), 0x00);
    }

    #[test]
    fn baud_rate_registers_round_trip() {
        let mut uart = VirtualUart::new();
        uart.write(reg::UARTIBRD, 26);
        uart.write(reg::UARTFBRD, 3);
        assert_eq!(uart.read(reg::UARTIBRD), 26);
        assert_eq!(uart.read(reg::UARTFBRD), 3);
    }

    #[test]
    fn control_registers_round_trip() {
        let mut uart = VirtualUart::new();
        uart.write(reg::UARTLCR_H, 0x70);
        uart.write(reg::UARTCR, 0x0301);
        assert_eq!(uart.read(reg::UARTLCR_H), 0x70);
        assert_eq!(uart.read(reg::UARTCR), 0x0301);
    }

    #[test]
    fn uartimsc_reads_zero() {
        let uart = VirtualUart::new();
        assert_eq!(uart.read(reg::UARTIMSC), 0);
    }

    #[test]
    fn uarticr_write_is_noop() {
        let mut uart = VirtualUart::new();
        let emit = uart.write(reg::UARTICR, 0x7FF);
        assert_eq!(emit, None);
    }

    #[test]
    fn unknown_offset_read_returns_zero() {
        let uart = VirtualUart::new();
        assert_eq!(uart.read(0x100), 0);
    }

    #[test]
    fn unknown_offset_write_returns_none() {
        let mut uart = VirtualUart::new();
        assert_eq!(uart.write(0x100, 42), None);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-hypervisor uart -- --nocapture`
Expected: FAIL — need to add `pub mod uart;` to lib.rs and implement read/write

- [ ] **Step 3: Add module to lib.rs**

In `crates/harmony-hypervisor/src/lib.rs`, add after the existing modules:

```rust
pub mod uart;
```

- [ ] **Step 4: Implement VirtualUart read/write methods**

Add to `uart.rs` after the `new()` method:

```rust
    /// Handle a register read. Returns the value to inject into the guest register.
    pub fn read(&self, offset: u16) -> u64 {
        match offset {
            reg::UARTDR => 0, // No RX data
            reg::UARTFR => UARTFR_TXFE_RXFE,
            reg::UARTIBRD => self.ibrd as u64,
            reg::UARTFBRD => self.fbrd as u64,
            reg::UARTLCR_H => self.lcr_h as u64,
            reg::UARTCR => self.cr as u64,
            reg::UARTIMSC => 0, // All interrupts masked
            reg::PERIPHID0 => PERIPHID[0],
            reg::PERIPHID1 => PERIPHID[1],
            reg::PERIPHID2 => PERIPHID[2],
            reg::PERIPHID3 => PERIPHID[3],
            _ => 0, // Unknown register reads as zero
        }
    }

    /// Handle a register write. Returns `Some(ch)` if a character was emitted (UARTDR write).
    pub fn write(&mut self, offset: u16, value: u64) -> Option<u8> {
        match offset {
            reg::UARTDR => Some((value & 0xFF) as u8),
            reg::UARTIBRD => { self.ibrd = (value & 0xFFFF) as u16; None }
            reg::UARTFBRD => { self.fbrd = (value & 0x3F) as u8; None }
            reg::UARTLCR_H => { self.lcr_h = (value & 0xFF) as u8; None }
            reg::UARTCR => { self.cr = (value & 0xFFFF) as u16; None }
            reg::UARTIMSC | reg::UARTICR => None, // Swallow interrupt config
            _ => None, // Unknown writes ignored
        }
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p harmony-hypervisor uart -- --nocapture`
Expected: PASS — all 10 tests

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-hypervisor/src/uart.rs crates/harmony-hypervisor/src/lib.rs
git commit -m "feat(hypervisor): add PL011 virtual UART register emulation"
```

---

### Task 2: Wire VirtualUart into Hypervisor

**Files:**
- Modify: `crates/harmony-hypervisor/src/vcpu.rs` (add uart field to Vm)
- Modify: `crates/harmony-hypervisor/src/hypervisor.rs` (delegate MMIO to VirtualUart)

**Context:** The `Vm` struct (vcpu.rs line 35-40) holds per-VM state. The MMIO handler (hypervisor.rs lines 265-303) currently has inline UART logic. We add a `VirtualUart` to each `Vm` and delegate the MMIO match to it.

- [ ] **Step 1: Write failing test for VirtualUart delegation**

Add to the existing test module in `hypervisor.rs`:

```rust
#[test]
fn uart_probe_sequence_emits_characters() {
    let mut hyp = make_test_hypervisor();
    let vmid = create_and_start_vm(&mut hyp);

    // Linux PL011 driver probe: read PeriphID registers
    let action = hyp.handle(TrapEvent::DataAbort {
        ipa: VIRTUAL_UART_IPA + 0xFE0, // PeriphID0
        access: AccessType::Read,
        width: 4,
        srt: 0,
    }, &mut test_frame_alloc).unwrap();
    match action {
        HypervisorAction::MmioResult { read_value, .. } => {
            assert_eq!(read_value, 0x11, "PeriphID0 should be 0x11");
        }
        _ => panic!("expected MmioResult"),
    }

    // Write a character via UARTDR
    let action = hyp.handle(TrapEvent::DataAbort {
        ipa: VIRTUAL_UART_IPA,
        access: AccessType::Write { value: 0x48 }, // 'H'
        width: 4,
        srt: 0,
    }, &mut test_frame_alloc).unwrap();
    match action {
        HypervisorAction::MmioResult { emit, .. } => {
            assert_eq!(emit, Some(0x48));
        }
        _ => panic!("expected MmioResult"),
    }
}
```

Note: Adapt `make_test_hypervisor` and `create_and_start_vm` helper names to match the existing test infrastructure in the file. If no such helpers exist, create minimal ones that call `hvc_vm_create` and `hvc_vm_start`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-hypervisor uart_probe -- --nocapture`
Expected: FAIL — PeriphID0 returns 0 (not yet delegated)

- [ ] **Step 3: Add VirtualUart to Vm struct**

In `crates/harmony-hypervisor/src/vcpu.rs`, add import and field:

```rust
use crate::uart::VirtualUart;
```

Add to the `Vm` struct (after `state` field at line 39):

```rust
pub struct Vm {
    pub id: VmId,
    pub vcpu: VCpuContext,
    pub stage2: Stage2PageTable,
    pub state: VmState,
    pub uart: VirtualUart,
}
```

- [ ] **Step 4: Update Vm creation in hypervisor.rs**

In `hypervisor.rs` where Vm is constructed (around line 130-136), add the uart field:

```rust
let vm = Vm {
    id: vmid,
    vcpu: VCpuContext::default(),
    stage2,
    state: VmState::Created,
    uart: VirtualUart::new(),
};
```

- [ ] **Step 5: Replace inline UART logic with VirtualUart delegation**

In `handle_data_abort` (lines 275-294), replace the inline match with delegation to the active VM's UART:

```rust
if (VIRTUAL_UART_IPA..VIRTUAL_UART_IPA + VIRTUAL_UART_SIZE).contains(&ipa) {
    let offset = (ipa - VIRTUAL_UART_IPA) as u16;
    let vmid = self.active_vmid.ok_or(HypervisorError::NoActiveVm)?;
    let vm = self.vms.get_mut(&vmid.0).ok_or(HypervisorError::InvalidVmId(vmid.0 as u64))?;

    let (emit, read_value) = match access {
        AccessType::Write { value } => (vm.uart.write(offset, value), 0),
        AccessType::Read => (None, vm.uart.read(offset)),
    };

    return Ok(HypervisorAction::MmioResult {
        emit,
        read_value,
        width,
        srt,
        pc_advance: 4,
    });
}
```

- [ ] **Step 6: Run all tests**

Run: `cargo test -p harmony-hypervisor -- --nocapture`
Expected: ALL pass (existing tests + new uart_probe test)

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-hypervisor/src/hypervisor.rs crates/harmony-hypervisor/src/vcpu.rs
git commit -m "feat(hypervisor): wire VirtualUart into per-VM state and MMIO dispatch"
```

---

### Task 3: VM_START dtb_ipa extension

**Files:**
- Modify: `crates/harmony-hypervisor/src/hypervisor.rs` (hvc_vm_start reads x3)
- Modify: `crates/harmony-hypervisor/src/trap.rs` (document x3 usage)

**Context:** `hvc_vm_start` (hypervisor.rs lines 167-193) currently takes `(x1=vmid, x2=entry_ipa)`. We add `x3=dtb_ipa` which gets written to `vcpu.x[0]` per ARM64 boot protocol (firmware passes DTB address in x0).

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn vm_start_sets_x0_to_dtb_ipa() {
    let mut hyp = make_test_hypervisor();
    let vmid = create_test_vm(&mut hyp); // create + map but don't start

    let entry_ipa = GUEST_RAM_BASE_IPA;
    let dtb_ipa = GUEST_RAM_BASE_IPA + 0x780_0000;

    let action = hyp.handle(TrapEvent::HvcCall {
        x0: HVC_VM_START,
        x1: vmid as u64,
        x2: entry_ipa,
        x3: dtb_ipa,
    }, &mut test_frame_alloc).unwrap();

    // Verify the guest would enter with x0 = dtb_ipa
    match action {
        HypervisorAction::EnterGuest { elr_el2, .. } => {
            assert_eq!(elr_el2, entry_ipa);
        }
        _ => panic!("expected EnterGuest"),
    }

    // Check that vcpu.x[0] was set to dtb_ipa
    let vm = hyp.vm(vmid).expect("vm should exist");
    assert_eq!(vm.vcpu.x[0], dtb_ipa);
}
```

- [ ] **Step 2: Add a `vm()` accessor to Hypervisor**

The `vms` field is private (`BTreeMap<u8, Vm>`). Add a test-accessible accessor in `hypervisor.rs`:

```rust
/// Read-only access to a VM by VMID (for testing and inspection).
pub fn vm(&self, vmid: u8) -> Option<&Vm> {
    self.vms.get(&vmid)
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p harmony-hypervisor vm_start_sets_x0 -- --nocapture`
Expected: FAIL — vcpu.x[0] is 0 (x3 not wired)

- [ ] **Step 4: Update hvc_vm_start to accept x3**

In `hypervisor.rs`, update the HVC dispatch for VM_START (around line 93 where HvcCall is matched) to pass x3:

Find where `HVC_VM_START` is matched and `hvc_vm_start(x1, x2)` is called. Change to `hvc_vm_start(x1, x2, x3)`.

Update the method signature:

```rust
fn hvc_vm_start(&mut self, x1: u64, x2: u64, x3: u64) -> Result<HypervisorAction, HypervisorError>
```

After setting `elr_el2` and `spsr_el2` (around line 183), add:

```rust
// ARM64 boot protocol: x0 = DTB physical address
vm.vcpu.x[0] = x3;
// x1, x2, x3 must be 0
vm.vcpu.x[1] = 0;
vm.vcpu.x[2] = 0;
vm.vcpu.x[3] = 0;
```

- [ ] **Step 5: Run all tests**

Run: `cargo test -p harmony-hypervisor -- --nocapture`
Expected: ALL pass

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-hypervisor/src/hypervisor.rs
git commit -m "feat(hypervisor): pass dtb_ipa via x3 in VM_START to vcpu.x[0]"
```

---

### Task 4: Device Tree Source and DTB Blob

**Files:**
- Create: `crates/harmony-hypervisor/dts/guest-virt.dts`
- Create: `crates/harmony-hypervisor/blobs/guest-virt.dtb` (compiled from DTS)

**Context:** Linux needs a DTB describing the virtual machine hardware. We write a minimal DTS and compile it with `dtc`. The `linux,initrd-end` is a placeholder — the guest loader patches it at runtime.

- [ ] **Step 1: Create DTS directory and source file**

```bash
mkdir -p crates/harmony-hypervisor/dts
```

Create `crates/harmony-hypervisor/dts/guest-virt.dts`:

```dts
/dts-v1/;

/ {
    compatible = "harmony,virt";
    #address-cells = <2>;
    #size-cells = <2>;

    cpus {
        #address-cells = <1>;
        #size-cells = <0>;
        cpu@0 {
            device_type = "cpu";
            compatible = "arm,armv8";
            reg = <0>;
        };
    };

    memory@40000000 {
        device_type = "memory";
        reg = <0x0 0x40000000 0x0 0x08000000>;
    };

    pl011@9000000 {
        compatible = "arm,pl011", "arm,primecell";
        reg = <0x0 0x09000000 0x0 0x1000>;
        clock-names = "uartclk", "apb_pclk";
        clocks = <&apb_pclk>, <&apb_pclk>;
    };

    apb_pclk: clock {
        compatible = "fixed-clock";
        #clock-cells = <0>;
        clock-frequency = <24000000>;
        clock-output-names = "clk24mhz";
    };

    chosen {
        bootargs = "earlycon=pl011,0x09000000 console=ttyAMA0";
        linux,initrd-start = <0x0 0x44000000>;
        linux,initrd-end = <0x0 0x44500000>;
    };
};
```

- [ ] **Step 2: Compile DTB**

```bash
mkdir -p crates/harmony-hypervisor/blobs
dtc -I dts -O dtb -o crates/harmony-hypervisor/blobs/guest-virt.dtb crates/harmony-hypervisor/dts/guest-virt.dts
```

If `dtc` is not installed: `nix-shell -p dtc` or `brew install dtc`.

- [ ] **Step 3: Verify DTB is valid**

```bash
dtc -I dtb -O dts crates/harmony-hypervisor/blobs/guest-virt.dtb > /dev/null
```

Expected: no errors (round-trip decompile succeeds)

- [ ] **Step 4: Add .gitattributes for binary blob**

Create or update `.gitattributes` at the repo root (if not already present):

```
crates/harmony-hypervisor/blobs/*.dtb binary
```

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-hypervisor/dts/guest-virt.dts crates/harmony-hypervisor/blobs/guest-virt.dtb .gitattributes
git commit -m "feat(hypervisor): add guest virtual machine device tree"
```

---

### Task 5: Guest Loader Module

**Files:**
- Create: `crates/harmony-microkernel/src/guest_loader.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs` (add mod)

**Context:** This module embeds the DTB blob and provides functions to prepare guest memory and boot a VM via HVC calls. The kernel Image and initramfs are NOT embedded yet (they require offline Alpine builds) — this task creates the loader infrastructure with the DTB and stub constants for the kernel/initramfs locations. The actual `include_bytes!` for kernel and initramfs will be added when the blobs are available.

The guest loader is a sans-I/O module — it produces a sequence of HVC call parameters that the caller executes. This keeps it testable without EL2 hardware.

- [ ] **Step 1: Write failing tests**

Create `crates/harmony-microkernel/src/guest_loader.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later

//! Guest VM boot orchestration.
//!
//! Prepares guest memory layout (kernel, initramfs, DTB) and produces
//! a sequence of HVC parameters for the caller to execute.

/// Embedded guest device tree blob (compiled from dts/guest-virt.dts).
static GUEST_DTB: &[u8] = include_bytes!("../../harmony-hypervisor/blobs/guest-virt.dtb");

/// Guest memory layout constants.
pub mod layout {
    /// Guest RAM base IPA (must match harmony-hypervisor GUEST_RAM_BASE_IPA).
    pub const RAM_BASE: u64 = 0x4000_0000;
    /// Guest RAM size: 128 MiB.
    pub const RAM_SIZE: u64 = 128 * 1024 * 1024;
    /// Kernel Image offset from RAM base (0 = loaded at base).
    pub const KERNEL_OFFSET: u64 = 0;
    /// Initramfs offset from RAM base (64 MiB).
    pub const INITRAMFS_OFFSET: u64 = 64 * 1024 * 1024;
    /// DTB offset from RAM base (120 MiB).
    pub const DTB_OFFSET: u64 = 120 * 1024 * 1024;

    /// IPA where kernel is loaded.
    pub const KERNEL_IPA: u64 = RAM_BASE + KERNEL_OFFSET;
    /// IPA where initramfs is loaded.
    pub const INITRAMFS_IPA: u64 = RAM_BASE + INITRAMFS_OFFSET;
    /// IPA where DTB is loaded.
    pub const DTB_IPA: u64 = RAM_BASE + DTB_OFFSET;
}

/// Patch the `linux,initrd-end` property in a DTB blob.
///
/// Searches for the placeholder value `0x44500000` (big-endian) and
/// replaces it with `initrd_end`. Returns `true` if the patch succeeded.
pub fn patch_dtb_initrd_end(dtb: &mut [u8], initrd_end: u64) -> bool {
    // The FDT stores the value as two big-endian u32 cells:
    // [high_be32, low_be32]. The placeholder high cell is 0x00000000
    // and low cell is 0x44500000.
    let placeholder_lo = 0x4450_0000u32.to_be_bytes();
    let placeholder_hi = 0u32.to_be_bytes();
    let needle: [u8; 8] = [
        placeholder_hi[0], placeholder_hi[1], placeholder_hi[2], placeholder_hi[3],
        placeholder_lo[0], placeholder_lo[1], placeholder_lo[2], placeholder_lo[3],
    ];

    let new_hi = ((initrd_end >> 32) as u32).to_be_bytes();
    let new_lo = (initrd_end as u32).to_be_bytes();

    // Find and replace the first occurrence
    for i in 0..dtb.len().saturating_sub(8) {
        if dtb[i..i + 8] == needle {
            dtb[i..i + 4].copy_from_slice(&new_hi);
            dtb[i + 4..i + 8].copy_from_slice(&new_lo);
            return true;
        }
    }
    false
}

/// Returns the embedded DTB blob.
pub fn guest_dtb() -> &'static [u8] {
    GUEST_DTB
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_constants_are_consistent() {
        assert_eq!(layout::KERNEL_IPA, 0x4000_0000);
        assert_eq!(layout::INITRAMFS_IPA, 0x4400_0000);
        assert_eq!(layout::DTB_IPA, 0x4780_0000);
        assert!(layout::DTB_OFFSET + 0x10000 <= layout::RAM_SIZE, "DTB must fit in RAM");
    }

    #[test]
    fn guest_dtb_is_valid_fdt() {
        let dtb = guest_dtb();
        assert!(dtb.len() > 40, "DTB too small to be valid");
        // FDT magic: 0xd00dfeed (big-endian)
        assert_eq!(&dtb[0..4], &[0xd0, 0x0d, 0xfe, 0xed], "bad FDT magic");
    }

    #[test]
    fn patch_dtb_initrd_end_replaces_placeholder() {
        let mut dtb = guest_dtb().to_vec();
        let initrd_end: u64 = 0x4432_0000; // example: 3.125 MiB initramfs
        assert!(patch_dtb_initrd_end(&mut dtb, initrd_end));

        // Verify the placeholder was replaced
        let needle = 0x4450_0000u32.to_be_bytes();
        let found = dtb.windows(4).any(|w| w == needle);
        assert!(!found, "placeholder should have been replaced");
    }

    #[test]
    fn patch_dtb_initrd_end_fails_on_missing_placeholder() {
        let mut buf = vec![0u8; 64]; // garbage, no FDT
        assert!(!patch_dtb_initrd_end(&mut buf, 0x4400_0000));
    }
}
```

- [ ] **Step 2: Add module to lib.rs**

In `crates/harmony-microkernel/src/lib.rs`, add after the existing modules:

```rust
pub mod guest_loader;
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel guest_loader -- --nocapture`
Expected: PASS — 4 tests (layout constants, FDT magic, patch success, patch fail)

Note: If the DTB blob path doesn't resolve from the microkernel crate, adjust the `include_bytes!` path. The relative path from `harmony-microkernel/src/guest_loader.rs` to `harmony-hypervisor/blobs/guest-virt.dtb` is `../../harmony-hypervisor/blobs/guest-virt.dtb`.

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-microkernel/src/guest_loader.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(microkernel): add guest loader module with DTB embedding and patching"
```

---

### Task 6: Kernel stub blob and boot sequence test

**Files:**
- Create: `crates/harmony-hypervisor/blobs/stub-kernel` (tiny test blob)
- Modify: `crates/harmony-microkernel/src/guest_loader.rs` (add boot orchestration)

**Context:** We can't embed a real Alpine kernel yet (requires offline build), but we can create a small stub that validates the entire boot path through the hypervisor. The stub is a minimal ARM64 binary that writes a known byte to the virtual UART then exits via HVC.

For unit testing the boot orchestration, we add a `BootPlan` struct that computes the HVC call sequence without actually calling HVC. This keeps the logic testable.

- [ ] **Step 1: Add BootPlan to guest_loader.rs**

```rust
/// A planned sequence of HVC operations to boot a guest VM.
/// Computed from blob sizes; the caller executes the actual HVC calls.
pub struct BootPlan {
    /// Total pages to allocate (RAM_SIZE / 4096).
    pub total_pages: u32,
    /// (ipa, page_count) pairs for VM_MAP calls (2 MiB chunks).
    pub map_chunks: alloc::vec::Vec<(u64, u16)>,
    /// Entry IPA (where kernel starts).
    pub entry_ipa: u64,
    /// DTB IPA (passed as x0 to guest).
    pub dtb_ipa: u64,
    /// Byte offsets within allocated RAM for blob copies.
    pub kernel_offset: u64,
    pub initramfs_offset: u64,
    pub dtb_offset: u64,
}

impl BootPlan {
    /// Compute a boot plan for the given blob sizes.
    pub fn new(kernel_size: usize, initramfs_size: usize, dtb_size: usize) -> Self {
        let total_pages = (layout::RAM_SIZE / 4096) as u32;

        // Build 2 MiB chunk list for VM_MAP
        let pages_per_chunk: u16 = 512; // 2 MiB / 4096
        let full_chunks = total_pages / pages_per_chunk as u32;
        let remainder = total_pages % pages_per_chunk as u32;

        let mut map_chunks = alloc::vec::Vec::new();
        for i in 0..full_chunks {
            let ipa = layout::RAM_BASE + (i as u64) * (pages_per_chunk as u64 * 4096);
            map_chunks.push((ipa, pages_per_chunk));
        }
        if remainder > 0 {
            let ipa = layout::RAM_BASE + (full_chunks as u64) * (pages_per_chunk as u64 * 4096);
            map_chunks.push((ipa, remainder as u16));
        }

        debug_assert!(kernel_size as u64 <= layout::INITRAMFS_OFFSET, "kernel too large");
        debug_assert!(
            layout::INITRAMFS_OFFSET + initramfs_size as u64 <= layout::DTB_OFFSET,
            "initramfs too large"
        );
        debug_assert!(
            layout::DTB_OFFSET + dtb_size as u64 <= layout::RAM_SIZE,
            "DTB doesn't fit"
        );

        Self {
            total_pages,
            map_chunks,
            entry_ipa: layout::KERNEL_IPA,
            dtb_ipa: layout::DTB_IPA,
            kernel_offset: layout::KERNEL_OFFSET,
            initramfs_offset: layout::INITRAMFS_OFFSET,
            dtb_offset: layout::DTB_OFFSET,
        }
    }
}
```

Add tests:

```rust
#[test]
fn boot_plan_computes_correct_chunks() {
    let plan = BootPlan::new(10 * 1024 * 1024, 3 * 1024 * 1024, 4096);
    // 128 MiB / 2 MiB = 64 chunks
    assert_eq!(plan.map_chunks.len(), 64);
    assert_eq!(plan.total_pages, 32768);
    assert_eq!(plan.entry_ipa, 0x4000_0000);
    assert_eq!(plan.dtb_ipa, 0x4780_0000);
    // First chunk starts at RAM base
    assert_eq!(plan.map_chunks[0], (0x4000_0000, 512));
    // Last chunk
    assert_eq!(plan.map_chunks[63], (0x4000_0000 + 63u64 * 2 * 1024 * 1024, 512));
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p harmony-microkernel boot_plan -- --nocapture`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-microkernel/src/guest_loader.rs
git commit -m "feat(microkernel): add BootPlan for guest VM memory mapping"
```

---

### Task 7: Virtual timer configuration

**Files:**
- Modify: `crates/harmony-hypervisor/src/platform/mod.rs` (add timer constants)
- Modify: `crates/harmony-hypervisor/src/hypervisor.rs` (add timer config method)

**Context:** Without timer access, the guest kernel faults on the first `mrs cntvct_el0` (counter read). The EL2 hypervisor must configure `CNTHCTL_EL2` to allow EL1 counter/timer access and zero `CNTVOFF_EL2`. These are per-VM settings applied before guest entry. In the sans-I/O model, the hypervisor tells the platform shim what values to write via the `EnterGuest` action.

Since the actual register writes happen in the platform shim (assembly), this task adds the configuration values to `EnterGuest` and documents the required platform shim behavior.

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn enter_guest_includes_timer_config() {
    let mut hyp = make_test_hypervisor();
    let vmid = create_and_start_vm(&mut hyp);

    match hyp.handle(TrapEvent::HvcCall {
        x0: HVC_VM_START,
        x1: vmid as u64,
        x2: GUEST_RAM_BASE_IPA,
        x3: GUEST_RAM_BASE_IPA + 0x780_0000,
    }, &mut test_frame_alloc).unwrap() {
        HypervisorAction::EnterGuest { cnthctl_el2, cntvoff_el2, .. } => {
            // EL1PCTEN (bit 0) and EL1PCEN (bit 1) must be set
            assert_ne!(cnthctl_el2 & 0b11, 0, "timer access bits must be set");
            assert_eq!(cntvoff_el2, 0, "virtual counter offset should be zero");
        }
        other => panic!("expected EnterGuest, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-hypervisor enter_guest_includes_timer -- --nocapture`
Expected: FAIL — `cnthctl_el2` field doesn't exist on `EnterGuest`

- [ ] **Step 3: Add timer fields to EnterGuest action**

In `crates/harmony-hypervisor/src/trap.rs`, add to the `EnterGuest` variant:

```rust
EnterGuest {
    vmid: VmId,
    stage2_root: PhysAddr,
    elr_el2: u64,
    spsr_el2: u64,
    cnthctl_el2: u64,   // NEW: timer access control for platform shim
    cntvoff_el2: u64,   // NEW: virtual counter offset
},
```

- [ ] **Step 4: Add timer constants to platform/mod.rs**

```rust
/// CNTHCTL_EL2 value for guest entry: EL1PCTEN (bit 0) + EL1PCEN (bit 1).
pub const GUEST_CNTHCTL_EL2: u64 = 0b11;
/// CNTVOFF_EL2 value: zero offset (virtual == physical counter).
pub const GUEST_CNTVOFF_EL2: u64 = 0;
```

- [ ] **Step 5: Populate timer fields in hvc_vm_start**

In `hypervisor.rs`, where `EnterGuest` is constructed in `hvc_vm_start` (around line 187-192), add the timer fields:

```rust
Ok(HypervisorAction::EnterGuest {
    vmid,
    stage2_root: vm.stage2.root(),
    elr_el2: entry_ipa,
    spsr_el2: 0x3C5,
    cnthctl_el2: GUEST_CNTHCTL_EL2,
    cntvoff_el2: GUEST_CNTVOFF_EL2,
})
```

Import the constants at the top of `hypervisor.rs`:
```rust
use crate::platform::{GUEST_CNTHCTL_EL2, GUEST_CNTVOFF_EL2, ...};
```

**Also update any other place that constructs `EnterGuest`** — search for `EnterGuest {` in the crate and add the two new fields to every construction site.

- [ ] **Step 6: Run all tests**

Run: `cargo test -p harmony-hypervisor -- --nocapture`
Expected: ALL pass

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-hypervisor/src/trap.rs crates/harmony-hypervisor/src/hypervisor.rs crates/harmony-hypervisor/src/platform/mod.rs
git commit -m "feat(hypervisor): add virtual timer config to EnterGuest action"
```

---

## Verification Checklist

After all tasks are complete:

- [ ] `cargo test -p harmony-hypervisor` — all tests pass
- [ ] `cargo test -p harmony-microkernel` — all tests pass
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` — no new warnings in modified crates
- [ ] `rustup run nightly cargo fmt --all -- --check` — formatted
- [ ] VirtualUart handles all 12 PL011 registers (unit tests)
- [ ] MMIO dispatch delegates to per-VM VirtualUart (integration test)
- [ ] VM_START passes dtb_ipa to vcpu.x[0] (unit test)
- [ ] DTB compiles from DTS without errors
- [ ] DTB embedded in guest_loader, FDT magic validated
- [ ] EnterGuest includes timer config (cnthctl_el2, cntvoff_el2)
- [ ] DTB initrd-end patching works (unit test)
- [ ] BootPlan computes correct 2 MiB chunk sequence (unit test)
