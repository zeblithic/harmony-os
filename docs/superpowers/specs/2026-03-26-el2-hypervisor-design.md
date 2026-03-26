# EL2 Micro-VM Hypervisor — Phase A+B1 Design

**Date:** 2026-03-26
**Status:** Draft
**Bead:** harmony-os-ikw (scoped to Phase A+B1)
**Follow-ups:** harmony-os-ohp (Alpine guest), harmony-os-o0d (GIC/IOMMU/shared-mem)

## Problem

Harmony OS needs to run unmodified Linux WiFi drivers (iwlwifi, brcmfmac) for mesh networking. These drivers are complex, hardware-specific, and unsafe to run in the kernel. The solution is EL2 virtualization: run the driver inside a lightweight Linux VM with PCIe device passthrough, isolated from the Harmony microkernel by hardware-enforced Stage-2 translation.

This spec covers the **foundation**: getting a working EL2 hypervisor that can boot a bare-metal guest stub. GIC virtualization, IOMMU passthrough, and shared memory are deferred to follow-up beads.

## Constraints

- **RPi5 UEFI hands off at EL2.** TF-A (`armstub8-2712.bin`) occupies EL3 for PSCI. UEFI runs at EL2 and passes that level to the OS. Harmony OS is already running at EL2 today without using EL2 features.
- **Sans-I/O pattern.** The hypervisor core is a pure state machine — no register access, no inline assembly. Events in, actions out. Testable with `cargo test`.
- **Dual platform.** Feature-gated `qemu-virt` and `rpi5` targets, matching the existing `platform.rs` pattern. Core logic is platform-agnostic.
- **Thin shim approach.** Minimal code at EL2 (~1000 lines). Microkernel stays at EL1 unchanged. HVC calls bridge EL1→EL2 for VM management.
- **Existing microkernel code unchanged.** The microkernel already configures EL1 registers. Today that works because it's running at EL2 accessing EL1 registers; after the change, it works correctly at EL1.

## Architecture

```
EL3: TF-A (PSCI via SMC — resident, not ours)
EL2: Thin hypervisor shim
     - VBAR_EL2 trap vectors (assembly, ~60 lines)
     - Hypervisor state machine (Rust, sans-I/O)
     - Stage-2 page table management
     - VM context save/restore
     - HVC dispatch
EL1: Harmony microkernel (host, "VM 0") | Guest VMs (isolated Stage-2)
EL0: Userspace processes
```

The hypervisor treats the host microkernel as "VM 0" — a context with no Stage-2 restriction (HCR_EL2.VM=0). Guest VMs get their own VMID and Stage-2 page tables. Context switching is uniform: save current vCPU, swap VTTBR_EL2, restore target vCPU.

## Crate Structure

New crate: `harmony-hypervisor`

| File | Responsibility |
|------|---------------|
| `src/lib.rs` | Public API, re-exports |
| `src/hypervisor.rs` | Sans-I/O `Hypervisor` state machine |
| `src/stage2.rs` | Stage-2 page table builder (IPA → PA) |
| `src/vcpu.rs` | vCPU context struct (saved EL1/EL2 registers) |
| `src/trap.rs` | `TrapEvent` / `HypervisorAction` types, HVC dispatch |
| `src/vmid.rs` | VMID allocator (8-bit, max 256 VMs) |
| `src/platform/mod.rs` | Platform trait for constants |
| `src/platform/qemu_virt.rs` | QEMU virt machine constants |
| `src/platform/rpi5.rs` | RPi5 BCM2712 constants |

**Dependency placement:** `harmony-hypervisor` is a workspace member — pure Rust, no bare-metal target requirement, testable with `cargo test --workspace`. The platform shim (assembly vectors + register access) lives in `harmony-boot-aarch64`, which depends on `harmony-hypervisor` with `default-features = false`. This keeps the sans-I/O core separate from the hardware-touching code.

The boot crate (`harmony-boot-aarch64`) gains:
- `el2_vectors.S` — VBAR_EL2 exception vector table (~60 lines asm)
- Boot sequence changes to configure EL2 and drop to EL1

## Sans-I/O Interface

### Events (input to hypervisor)

```rust
pub enum TrapEvent {
    /// HVC call from EL1 (microkernel or guest).
    /// Registers x0-x3 are passed directly from the trap frame.
    HvcCall { x0: u64, x1: u64, x2: u64, x3: u64 },
    /// Stage-2 data abort (guest accessed unmapped/trapped IPA).
    /// The platform shim decodes ESR_EL2.ISS: the IPA comes from HPFAR_EL2,
    /// `width` from ISS.SAS, and for writes the `value` is read from the
    /// saved register file using ISS.SRT as the index.
    DataAbort { ipa: u64, access: AccessType, width: u8 },
    /// Stage-2 instruction abort
    InstructionAbort { ipa: u64 },
    /// Guest executed WFI/WFE
    WfiWfe,
    /// SMC from EL1 that needs forwarding to EL3 (PSCI).
    /// The platform shim must advance ELR_EL2 by 4 after handling,
    /// because SMC traps set ELR_EL2 to the SMC instruction itself.
    SmcForward { x0: u64, x1: u64, x2: u64, x3: u64 },
}

pub enum AccessType {
    Read,
    Write { value: u64 },
}
```

### Actions (output from hypervisor)

The `handle()` method returns a single action per trap — each trap has exactly one logical response. Compound operations (create VM + map memory + start) are driven by multiple HVC calls from EL1, not batched. This avoids heap allocation in the EL2 trap path.

```rust
pub enum HypervisorAction {
    /// Resume the currently active guest
    ResumeGuest,
    /// Create a new VM with the given VMID and Stage-2 root
    CreateVm { vmid: VmId, stage2_root: PhysAddr },
    /// Destroy a VM and free its resources
    DestroyVm { vmid: VmId },
    /// Add a Stage-2 mapping for a VM.
    /// The platform shim must perform TLB invalidation after executing this:
    /// TLBI IPAS2E1IS, TLBI VMALLE1IS, DSB ISH, ISB.
    MapStage2 { vmid: VmId, ipa: u64, pa: PhysAddr, flags: Stage2Flags },
    /// Virtual UART output (trapped MMIO write → host console), then resume guest
    EmitChar { ch: u8 },
    /// Forward an SMC to EL3 (PSCI), advance ELR_EL2 += 4, then resume guest
    ForwardSmc { x0: u64, x1: u64, x2: u64, x3: u64 },
    /// Switch to guest context and eret
    EnterGuest { vmid: VmId },
    /// Return a value to the HVC caller and resume at EL1
    HvcResult { x0: u64 },
}
```

### HVC Function IDs

```rust
pub const HVC_VM_CREATE: u64  = 0x4856_0001;  // Create VM, returns VMID
pub const HVC_VM_DESTROY: u64 = 0x4856_0002;  // Destroy VM by VMID
pub const HVC_VM_START: u64   = 0x4856_0003;  // Enter guest at entry point
pub const HVC_VM_MAP: u64     = 0x4856_0010;  // Map IPA range for a VM
pub const HVC_GUEST_EXIT: u64 = 0x4856_0099;  // Guest voluntary exit
```

The `0x4856` prefix is "HV" in ASCII, placing these in the vendor-specific HVC range.

### HVC Register Conventions

| HVC | x0 | x1 | x2 | x3 | Returns (x0) |
|-----|----|----|----|----|-------------|
| VM_CREATE | function ID | 0 | 0 | 0 | VMID (or negative error) |
| VM_DESTROY | function ID | VMID | 0 | 0 | 0 (or negative error) |
| VM_START | function ID | VMID | entry_ipa | 0 | 0 (or negative error) |
| VM_MAP | function ID | VMID \| (flags << 8) \| (page_count << 16) | ipa | pa | 0 (or negative error) |
| GUEST_EXIT | function ID | exit_code | 0 | 0 | (does not return to guest) |

For VM_MAP, `x1` packs three fields: bits [7:0] = VMID, bits [15:8] = Stage2Flags encoded as a bitfield (R=bit0, W=bit1, X=bit2, MemAttr=bits[5:3]), bits [31:16] = page count. This fits all parameters in 4 registers without needing x4+.

## Stage-2 Page Tables

Stage-2 uses the same 4-level, 4KiB granule, 512-entry-per-table structure as the existing Stage-1 in `vm/aarch64.rs`, but with different descriptor bits:

| Aspect | Stage-1 (existing) | Stage-2 (new) |
|--------|-------------------|---------------|
| Register | TTBR0_EL1 | VTTBR_EL2 |
| Control | TCR_EL1 | VTCR_EL2 |
| Input | VA | IPA |
| Output | PA | PA |
| Permissions | AP[2:1] | S2AP[1:0] (different encoding) |
| Execute | UXN, PXN | XN[1:0] |
| Memory type | MAIR index (3 bits) | Direct MemAttr[3:0] (no MAIR) |

```rust
/// VMID newtype — 8-bit namespace, max 256 VMs (0 reserved for host).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VmId(pub u8);

pub struct Stage2PageTable {
    root: PhysAddr,
    vmid: VmId,
    /// Same pattern as Aarch64PageTable — converts PA to kernel-accessible pointer.
    phys_to_virt: fn(PhysAddr) -> *mut u8,
}

pub struct Stage2Flags {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub mem_attr: Stage2MemAttr,
}

pub enum Stage2MemAttr {
    NormalWriteBack,   // MemAttr = 0b1111
    NormalNonCacheable, // MemAttr = 0b0101
    Device,            // MemAttr = 0b0000
}
```

Frame allocation for Stage-2 table pages uses the existing `BuddyAllocator`.

VTCR_EL2 configuration: T0SZ=24 (40-bit IPA space), TG0=4KiB, SL0=level 0 start, SH0/ORGN0/IRGN0=inner-shareable write-back.

## vCPU Context

```rust
pub struct VCpuContext {
    // General-purpose registers
    pub x: [u64; 31],
    pub sp_el0: u64,              // Guest EL0 stack pointer
    pub sp_el1: u64,              // Guest EL1 stack pointer

    // Trap state (saved by hardware on trap to EL2)
    pub elr_el2: u64,             // Guest PC at trap point
    pub spsr_el2: u64,            // Guest PSTATE at trap point

    // EL1 system registers the guest owns
    pub sctlr_el1: u64,
    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
    pub tcr_el1: u64,
    pub mair_el1: u64,
    pub vbar_el1: u64,
    pub elr_el1: u64,             // Guest's own EL1 trap return address
    pub spsr_el1: u64,            // Guest's own EL1 saved PSTATE
    pub contextidr_el1: u64,

    // Virtual timer
    pub cntv_ctl_el0: u64,
    pub cntv_cval_el0: u64,
}

pub struct Vm {
    pub id: VmId,
    pub vcpu: VCpuContext,
    pub stage2: Stage2PageTable,
    pub state: VmState,
}

pub enum VmState {
    Created,
    Running,
    Halted,
}
```

The host microkernel is "VM 0" — a `VCpuContext` without Stage-2 restriction. The asm shim saves `ELR_EL2` and `SPSR_EL2` (hardware trap state) into the current vCPU's context on every trap, and restores them on `eret`. Context switch: save current vCPU registers (GPRs + system regs + ELR/SPSR_EL2) → swap VTTBR_EL2 (or clear HCR_EL2.VM for host) → restore target vCPU registers → `eret`.

## Boot Sequence

### Before (current — everything at EL2 using EL1 regs)

```
UEFI → ExitBootServices → boot entry (EL2)
  → configure MAIR_EL1, TCR_EL1, TTBR0_EL1, SCTLR_EL1
  → install VBAR_EL1
  → jump to microkernel
```

### After (EL2 shim installed, microkernel at EL1)

```
UEFI → ExitBootServices → boot entry (EL2)
  → read CurrentEL, assert EL2
  → install VBAR_EL2 (hypervisor trap vectors)
  → configure HCR_EL2:
      VM=0    (no Stage-2 for host)
      HCD=0   (HVC enabled)
      RW=1    (EL1 is AArch64)
      TSC=1   (trap SMC to EL2 for PSCI forwarding)
  → configure VTCR_EL2 (Stage-2 format: 4KiB, 40-bit IPA)
  → initialize Hypervisor state machine
  → set ELR_EL2 = microkernel entry point
  → set SPSR_EL2 = EL1h, all exceptions masked
  → eret (drops to EL1)
  → microkernel runs at EL1 (existing register setup unchanged)
```

## Guest Stub (Phase B1 Test Fixture)

A minimal aarch64 binary at `crates/harmony-hypervisor/tests/fixtures/guest_stub.S`:

1. Writes "Hello from guest\n" to virtual UART at IPA `0x0900_0000` (a conventional virtual device IPA, not a real hardware address — platform-independent because it's trapped by Stage-2 fault, not passed through)
2. Calls `HVC #0` with `x0=HVC_GUEST_EXIT, x1=0` (success)
3. Falls through to WFI loop as safety net

The virtual UART works via Stage-2 data abort: IPA `0x0900_0000` is unmapped in the guest's Stage-2 tables. Guest store → Stage-2 fault → hypervisor recognizes UART IPA → returns `EmitChar`. Zero emulation code in the guest.

Pre-compiled into a `&[u8]` constant for unit tests.

## Error Handling

```rust
pub enum HypervisorError {
    VmLimitReached,
    InvalidVmId(VmId),
    InvalidHvc(u64),
    Stage2MapFailed(VmError),
    VmAlreadyRunning(VmId),
    OutOfMemory,
}
```

`Hypervisor::handle()` returns `Result<HypervisorAction, HypervisorError>` — a single action per trap, no heap allocation. The platform shim translates errors to negative HVC return codes. Invalid guest traps (unmapped IPA that isn't a virtual device) result in `DestroyVm` — kill the guest, never the hypervisor.

## Testing Strategy

| Layer | What | How |
|-------|------|-----|
| Unit tests | State machine, Stage-2 logic, VMID allocator | `cargo test` — pure Rust, no hardware |
| Mock platform | Full VM lifecycle (create→map→start→trap→exit) | `MockPlatform` feeding `TrapEvent` sequences |
| QEMU integration | Real EL2 vectors, real Stage-2, real `eret` | `cargo test --features qemu-virt` under QEMU `-machine virt,virtualization=on` |
| RPi5 smoke | Same binary on hardware | Manual, CI later |

QEMU integration tests use a custom `#![no_main]` harness with semihosting exit for pass/fail reporting.

**Critical first test:** The QEMU integration suite must begin with a focused EL2→EL1 drop test: boot at EL2, install vectors, `eret` to EL1, read `CurrentEL` to assert EL1 (`0x4`), issue `HVC #0` with a ping function ID, verify the return value. This validates the most dangerous operation (the initial exception level transition) before anything else.

## Out of Scope

- GICv3 virtual interrupt injection (harmony-os-o0d)
- BCM2712 SMMU/IOMMU passthrough (harmony-os-o0d)
- Shared memory data plane (harmony-os-o0d)
- Booting a real Linux kernel (harmony-os-ohp)
- Multi-vCPU support
- VHE (Approach C upgrade path — not needed for 1-2 VMs)
- 9P control plane for VM lifecycle (harmony-os-o0d)
