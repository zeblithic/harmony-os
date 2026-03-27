# Boot Alpine Linux Guest in EL2 Micro-VM — Design Spec

## Goal

Boot a minimal Alpine Linux kernel inside the EL2 micro-VM hypervisor to
the point where earlycon prints boot messages on the virtual UART. This
validates real-world kernel compatibility of the hypervisor plumbing built
in harmony-os-ikw. Success = seeing `"Booting Linux"` on the virtual
console.

## Background

The EL2 hypervisor (harmony-hypervisor crate) provides a sans-I/O state
machine with `TrapEvent` → `HypervisorAction` dispatch, Stage-2 page
tables, HVC-based VM lifecycle (create/map/start/destroy), and a minimal
virtual UART stub. The existing UART stub handles only UARTDR write and
UARTFR read — too minimal for Linux's PL011 driver probe.

GIC virtual interrupt injection is a separate follow-up bead
(harmony-os-04p). Without GIC, the kernel will boot through earlycon,
memory init, and driver probe, then hang when it needs timer tick
interrupts. This is the expected stopping point.

## Design Decisions

- **Earlycon milestone**: Boot far enough for Linux to print early
  messages. No attempt to reach userspace or fully boot.
- **Embedded blobs**: Kernel Image, initramfs, and DTB compiled offline
  and embedded via `include_bytes!()`. Self-contained, deterministic.
- **Hand-written DTS**: ~30-line source compiled with `dtc`, DTB
  committed to repo. Initrd-end patched at runtime.
- **PL011 probe subset**: Stub ~12 registers (not just earlycon's 2) so
  the full driver probe doesn't kill the guest.
- **128 MiB guest RAM**: Comfortable headroom for kernel + initramfs.
- **No GIC, no virtio**: Timer configured for counter reads only;
  interrupts pend but never deliver.

## PL011 Virtual UART

New `uart.rs` module in `harmony-hypervisor`. The hypervisor's MMIO
handler delegates UART-range traps (IPA `0x0900_0000–0x0900_0FFF`) to a
`VirtualUart` struct owned by each VM.

### Register Map

| Offset | Register | Read | Write |
|--------|----------|------|-------|
| 0x000 | UARTDR | 0 (no RX) | Emit character |
| 0x018 | UARTFR | 0x90 (TXFE\|RXFE) | — (read-only) |
| 0x024 | UARTIBRD | Stored value | Store (no effect) |
| 0x028 | UARTFBRD | Stored value | Store (no effect) |
| 0x02C | UARTLCR_H | Stored value | Store (no effect) |
| 0x030 | UARTCR | Stored value | Store (no effect) |
| 0x038 | UARTIMSC | 0 | Store (no effect) |
| 0x044 | UARTICR | — | Store (clear, no-op) |
| 0xFE0 | PeriphID0 | 0x11 | — |
| 0xFE4 | PeriphID1 | 0x10 | — |
| 0xFE8 | PeriphID2 | 0x34 | — |
| 0xFEC | PeriphID3 | 0x00 | — |

PeriphID `0x00341011` identifies a PL011 rev r1p5 — the ID Linux's
`amba-pl011.c` driver expects. All other offsets read as 0, writes are
silently swallowed.

### VirtualUart Struct

```rust
pub struct VirtualUart {
    ibrd: u16,
    fbrd: u8,
    lcr_h: u8,
    cr: u16,
}
```

### MMIO Interface

```rust
impl VirtualUart {
    pub fn read(&self, offset: u16) -> u64
    pub fn write(&mut self, offset: u16, value: u64) -> Option<u8>
}
```

`write` returns `Some(ch)` when a character is emitted (UARTDR write),
`None` otherwise. The hypervisor translates this to `MmioResult { emit }`.

## Guest Memory Layout

128 MiB at IPA `0x4000_0000` (existing `GUEST_RAM_BASE_IPA`):

```
IPA 0x4000_0000  ┌──────────────────────┐
                 │  Linux Image          │  RAM base, 2 MiB aligned
                 │  (~10-15 MB)          │
                 ├──────────────────────┤
IPA 0x4400_0000  │  Initramfs           │  +64 MiB offset
                 │  (~2-5 MB)           │
                 ├──────────────────────┤
IPA 0x4780_0000  │  DTB                 │  +120 MiB offset
                 │  (~4 KB)             │
                 ├──────────────────────┤
IPA 0x4800_0000  └──────────────────────┘  RAM end
```

### ARM64 Boot Protocol

- Kernel Image at 2 MiB-aligned offset from RAM base
- DTB 8-byte aligned, within 512 MiB of kernel
- Entry: `x0 = DTB physical address`, `x1 = x2 = x3 = 0`
- `spsr_el2 = 0x3C5` (EL1h, DAIF masked)

## Guest Loader

New `guest_loader.rs` module in `harmony-microkernel`.

### Embedded Blobs

```rust
static KERNEL_IMAGE: &[u8] = include_bytes!("../blobs/alpine-kernel-Image");
static INITRAMFS: &[u8] = include_bytes!("../blobs/alpine-initramfs.cpio.gz");
static GUEST_DTB: &[u8] = include_bytes!("../blobs/guest-virt.dtb");
```

### Boot Sequence

1. `hvc(VM_CREATE)` → receive VMID.
2. Allocate 32,768 physical frames (128 MiB) from buddy allocator.
3. Copy `KERNEL_IMAGE` to frame offset 0x0.
4. Copy `INITRAMFS` to frame offset `0x400_0000`.
5. Patch DTB `linux,initrd-end` with `0x4400_0000 + INITRAMFS.len()`.
6. Copy patched DTB to frame offset `0x780_0000`.
7. Issue `hvc(VM_MAP)` in 2 MiB chunks (512 pages each, ~64 HVC calls)
   with `GUEST_RAM` flags (RWX, Normal WriteBack).
8. `hvc(VM_START, vmid, entry_ipa=0x4000_0000, dtb_ipa=0x4780_0000)` —
   maps to x0=func, x1=vmid, x2=entry, x3=dtb.

### HVC VM_START Change

Extend VM_START to accept `x3 = dtb_ipa` (x0=function_id, x1=vmid,
x2=entry_ipa, x3=dtb_ipa). The hypervisor writes `dtb_ipa` to
`vcpu.x[0]` before guest entry, following the ARM64 boot protocol
convention where firmware passes DTB address in x0.

## Device Tree Source

Checked into `crates/harmony-hypervisor/dts/guest-virt.dts`:

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

No `interrupt-parent` or GIC node. The PL011 node omits `interrupts` —
the full driver fails to claim IRQ but earlycon continues.

`linux,initrd-end` is a placeholder — the guest loader patches it at
runtime with the actual initramfs size.

## Virtual Timer Configuration

Platform shim configuration only (no hypervisor state machine changes):

- `CNTHCTL_EL2.EL1PCTEN = 1` — guest can read physical counter
- `CNTHCTL_EL2.EL1PCEN = 1` — guest can access physical timer
- `CNTVOFF_EL2 = 0` — virtual counter equals physical counter

The vCPU context already saves/restores `cntv_ctl_el0` and
`cntv_cval_el0`. Timer interrupts (PPI 27) pend but never deliver without
GIC — the kernel uses the counter for timestamps but the tick never fires.

## New File

`crates/harmony-hypervisor/src/uart.rs` — VirtualUart struct and register
emulation.

## Modified Files

- `crates/harmony-hypervisor/src/hypervisor.rs` — delegate UART MMIO to
  VirtualUart, add VM_START dtb_ipa parameter, store VirtualUart per VM
- `crates/harmony-hypervisor/src/trap.rs` — update VM_START to accept
  dtb_ipa in x3
- `crates/harmony-microkernel/src/guest_loader.rs` — new module for
  embedded blob loading and VM boot orchestration
- Platform shim — set CNTHCTL_EL2 and CNTVOFF_EL2 during hypervisor init

## Testing

### Unit Tests (harmony-hypervisor)

- PL011 register reads: PeriphID0-3 return correct values, UARTFR
  returns 0x90, stored registers round-trip
- PL011 writes: UARTDR emits character, UARTCR/LCR_H/IBRD/FBRD store
  without side effects, UARTICR write is no-op
- Unknown UART offset: read returns 0, write silently ignored
- VM_START with dtb_ipa: x3 parameter propagates to vcpu.x[0]
- Boot trap sequence: simulate ~20 traps (PeriphID reads, UARTCR config,
  earlycon writes), verify emitted characters

### Integration Test (QEMU)

- Guest loader allocates frames, copies blobs, maps via HVC, starts VM
- Microkernel collects emitted characters from MmioResult actions
- Success: buffer contains `"Booting Linux"` substring
- Timeout: report failure if no characters after N iterations

### Offline CI Checks

- `dtc` compiles `guest-virt.dts` without errors
- Embedded blobs exist and are non-empty
- Kernel Image has ARM64 magic `0x644d5241` at offset 0x38

## Out of Scope

- GIC emulation (harmony-os-04p)
- Timer interrupt delivery
- Multi-vCPU
- Virtio devices
- Guest UART RX (no input path)
- Runtime kernel loading from USB/network
- Full boot to userspace
- KASLR (needs entropy source)
