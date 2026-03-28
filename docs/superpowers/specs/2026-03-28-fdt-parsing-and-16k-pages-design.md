# FDT Device Tree Parsing and 16KiB Page Granule Support

**Date:** 2026-03-28
**Status:** Draft
**Beads:** harmony-os-mn0 (FDT parsing), harmony-os-ded (16K pages)

## Problem

Harmony OS discovers hardware through hardcoded addresses (x86_64: PCI scan for VirtIO, aarch64: compile-time feature flags for QEMU virt vs RPi5). This prevents supporting platforms where hardware layout varies per device — most critically Apple Silicon, where m1n1 provides a Flattened Device Tree (FDT) describing the specific SoC variant.

Separately, Apple Silicon's DART IOMMU hardware requires 16KiB page alignment. The host kernel must use 16K pages. The current page table, buddy allocator, and Linuxulator all hardcode `PAGE_SIZE = 4096`. Supporting Apple Silicon requires making the page granule configurable at compile time.

These two features are designed together because they're prerequisites for the same target (Apple Silicon Phases A and C) and interact at the boot path — FDT parsing discovers the platform, and the page granule must match what the platform requires.

## Constraints

- **No new crates in the workspace.** FDT parsing is a module in `harmony-boot-aarch64`, not a standalone crate. The `fdt` crate (crates.io, no_std, zero-alloc) is the only new external dependency, added only to boot stubs.
- **Compile-time page granule.** Feature flag `page-16k` on `harmony-microkernel`, not runtime-configurable. Exception: hypervisor stage-2 paging uses runtime granule for guests.
- **Honest Linuxulator.** On a 16K host, `sysconf(_SC_PAGESIZE)` returns 16384. No 4K emulation. Binaries requiring 4K pages use the hypervisor microVM path (Phase D+).
- **No Apple Silicon hardware dependency.** Everything testable via QEMU (TCG supports 16K page guests, standard DTBs available for virt machine).

## Architecture

### HardwareConfig — Platform-Agnostic Hardware Descriptor

FDT parsing, UEFI discovery, and hardcoded constants all converge on a single struct that the runtime consumes. The runtime never knows which source populated it.

```rust
/// Platform-agnostic hardware descriptor, populated at boot from
/// FDT, UEFI, or hardcoded constants depending on the boot path.
pub struct HardwareConfig {
    /// System memory regions (base, size) from /memory nodes.
    pub memory_regions: Vec<MemoryRegion>,
    /// Serial console for early debug output.
    pub serial: Option<SerialConfig>,
    /// Interrupt controller (GIC or AIC).
    pub interrupt_controller: Option<InterruptControllerConfig>,
    /// Network interfaces discovered from device tree.
    pub network_devices: Vec<NetworkDeviceConfig>,
    /// Block storage devices.
    pub block_devices: Vec<BlockDeviceConfig>,
    /// Chosen node data (/chosen: bootargs, stdout-path, initrd).
    pub chosen: ChosenConfig,
    /// Page granule reported by firmware/platform (4096 or 16384).
    pub page_granule: usize,
}
```

Each sub-config holds MMIO base address, size, interrupt number, and `compatible` string. The struct lives in `harmony-microkernel` (Ring 2+ all consume it), and Ring 1 can also use it via dependency.

**Population paths:**
- **FDT path (new):** Boot stub receives DTB pointer → `fdt` crate parses → populates `HardwareConfig`.
- **UEFI path (existing):** Boot stub queries UEFI protocols → populates `HardwareConfig` from results + platform feature flags.
- **Hardcoded path (existing):** Compile-time constants fill `HardwareConfig` directly.

### FDT Parsing Module

A `fdt_parse` module inside `harmony-boot-aarch64` that takes a raw DTB pointer and produces `HardwareConfig`. Not a general-purpose FDT abstraction — just the specific node/property lookups needed for boot.

**Nodes parsed:**

| FDT Path | Property | Maps To |
|---|---|---|
| `/memory@*` | `reg` (base, size pairs) | `memory_regions` |
| `/chosen` | `bootargs`, `stdout-path`, `linux,initrd-start/end` | `chosen` |
| `compatible = "arm,pl011"` or `"apple,uart"` | `reg`, `interrupts` | `serial` |
| `compatible = "arm,gic-v3"` or `"apple,aic"` | `reg`, variant | `interrupt_controller` |
| `compatible = "virtio,mmio"` or known NIC strings | `reg`, `interrupts` | `network_devices` |
| `compatible = "nvme"` or `"apple,ans2"` | `reg`, `interrupts` | `block_devices` |

**Dependency:** `fdt` crate (no_std, zero-alloc) added to `harmony-boot-aarch64/Cargo.toml` only. The `fdt` crate is not a dependency of the microkernel or runtime.

**Error handling:** Missing nodes are `None` in `HardwareConfig`. Missing `/memory` is fatal (panic — can't proceed without RAM). Everything else degrades gracefully. The boot stub logs what it found via serial console.

### 16KiB Page Granule — Compile-Time Feature Flag

The `page-16k` feature on `harmony-microkernel` switches the fundamental page constants:

```rust
// harmony-microkernel/src/vm/mod.rs

#[cfg(not(feature = "page-16k"))]
pub const PAGE_SIZE: u64 = 4096;
#[cfg(not(feature = "page-16k"))]
pub const PAGE_SHIFT: u32 = 12;

#[cfg(feature = "page-16k")]
pub const PAGE_SIZE: u64 = 16384;
#[cfg(feature = "page-16k")]
pub const PAGE_SHIFT: u32 = 14;
```

**Feature propagation:** Downstream crates add passthrough in their `Cargo.toml`:

```toml
[features]
page-16k = ["harmony-microkernel/page-16k"]
```

Boot stubs select the feature based on their target platform. `harmony-boot-aarch64` with `rpi5` or `qemu-virt` does NOT enable `page-16k`. A future `apple-silicon` feature (Phase D) would.

**Validation:** `const_assert!` at the top of the aarch64 page table module ensures `page-16k` cannot be enabled on x86_64.

### Aarch64 Page Table Geometry

ARM64 page table structure changes significantly with 16K granule:

**4KiB granule (current):**
- 4 levels: L0 → L1 → L2 → L3
- 9 bits per level index, 512 entries per table
- Each table = 512 × 8 bytes = 4KiB (one page)
- VA: 12 + 9 + 9 + 9 + 9 = 48-bit

**16KiB granule:**
- 3 levels: L1 → L2 → L3 (L0 unused — 47-bit VA is sufficient)
- 11 bits per level index, 2048 entries per table
- Each table = 2048 × 8 bytes = 16KiB (one page)
- VA: 14 + 11 + 11 + 11 = 47-bit

**Implementation:** A `geometry` module switches on the feature flag:

```rust
#[cfg(not(feature = "page-16k"))]
mod geometry {
    pub const ENTRIES_PER_TABLE: usize = 512;
    pub const LEVEL_BITS: u32 = 9;
    pub const TABLE_LEVELS: usize = 4;  // L0..L3
    pub const START_LEVEL: usize = 0;
}

#[cfg(feature = "page-16k")]
mod geometry {
    pub const ENTRIES_PER_TABLE: usize = 2048;
    pub const LEVEL_BITS: u32 = 11;
    pub const TABLE_LEVELS: usize = 3;  // L1..L3
    pub const START_LEVEL: usize = 1;
}
```

The page table walk generalizes from the current hardcoded `(vaddr >> (12 + level * 9)) & 0x1FF` to `(vaddr >> (PAGE_SHIFT + level * LEVEL_BITS)) & ((1 << LEVEL_BITS) - 1)`.

**USER_SPACE_END:** Derived from constants instead of hardcoded. With 4K: `(1 << 48) - PAGE_SIZE`. With 16K: `(1 << 47) - PAGE_SIZE`.

**TCR_EL1:** The boot stub's MMU setup sets granule bits: `TG0` = `0b00` (4K) or `0b10` (16K); `TG1` = `0b10` (4K) or `0b01` (16K). Lives in the boot crate, not the microkernel.

### Buddy Allocator Adaptation

The buddy allocator adapts with zero code changes. It already uses `PAGE_SIZE` and `PAGE_SHIFT` for all frame arithmetic. With `page-16k`:
- Order 0 = 16KiB, order 10 = 16MiB
- Per-frame bitmap: 1 bit per 16KiB frame
- Split/coalesce math unchanged — all expressed as `1u64 << (order + PAGE_SHIFT)`

Verification needed: `add_region` correctly aligns start/end to 16KiB boundaries. The existing code aligns to `PAGE_SIZE`, so this should work. Tests confirm.

### Hypervisor Stage-2 — Runtime Granule for Guests

The host hypervisor is compiled with the host's page granule but must manage stage-2 mappings for guests that use a different granule.

```rust
pub enum Stage2Granule {
    Four,    // 4KiB guest pages
    Sixteen, // 16KiB guest pages
}

pub struct Stage2PageTable {
    granule: Stage2Granule,
    // ... existing fields
}
```

Stage-2 `map`/`unmap` branch on `granule` for index arithmetic and descriptor format. Not hot-path — stage-2 mappings are set up at VM creation, not per-access.

**VTCR_EL2:** `TG0` set at VM creation to match the guest's granule.

### Linuxulator Changes

The local `const PAGE_SIZE: usize = 4096` at linuxulator.rs:1749 is replaced with an import from `harmony_microkernel::vm::PAGE_SIZE`. All existing mmap/brk/mprotect rounding logic already uses `PAGE_SIZE` — it just needs to come from the right source.

On a 16K host, `sysconf(_SC_PAGESIZE)` returns 16384. No emulation, no sub-page tracking. Binaries requiring 4K pages use the hypervisor microVM path (Phase D+).

## Testing Strategy

| Test | What | Granule |
|---|---|---|
| `fdt_parse_qemu_virt` | Parse QEMU virt machine DTB, verify PL011 + GIC + VirtIO discovered | N/A |
| `fdt_parse_memory_regions` | Synthetic DTB with multiple `/memory` nodes | N/A |
| `fdt_missing_memory_panics` | DTB without `/memory` → panic | N/A |
| `fdt_unknown_compatible_ignored` | Unknown `compatible` strings → `None` fields, no crash | N/A |
| `fdt_chosen_bootargs` | `/chosen` with bootargs, stdout-path → correct `ChosenConfig` | N/A |
| `page_table_map_unmap_4k` | Existing tests, unchanged | 4K |
| `page_table_map_unmap_16k` | Same tests compiled with `--features page-16k` — 3-level walk, 16K alignment | 16K |
| `page_table_47bit_va_limit` | Map at max 47-bit VA boundary, reject 48-bit addresses | 16K |
| `buddy_allocator_16k` | Frame size = 16KiB, split/coalesce correct, alignment verified | 16K |
| `linuxulator_mmap_16k` | mmap with 4K-aligned hint → rounds up to 16K boundary | 16K |
| `linuxulator_brk_16k` | brk alignment at 16KiB | 16K |
| `stage2_4k_guest_on_16k_host` | Stage-2 with `Stage2Granule::Four`, verify 4K IPA mappings | Both |
| `stage2_16k_guest` | Stage-2 with `Stage2Granule::Sixteen`, verify 16K IPA mappings | 16K |
| `qemu_boot_fdt_integration` | Boot aarch64 QEMU, parse FDT, discover hardware dynamically | 4K |

Tests for `page-16k` run in CI as a separate job: `cargo test -p harmony-microkernel --features page-16k`.

QEMU 16K testing: `qemu-system-aarch64 -cpu max,pagesize=16k` with TCG backend.

## Out of Scope

- **Apple Silicon boot (Phase D)** — m1n1 integration, AIC driver, PMGR power management.
- **DART IOMMU (Phase E)** — DMA isolation with capability integration.
- **4K page emulation in Linuxulator** — deliberately excluded. The hypervisor microVM is the right answer.
- **x86_64 FDT support** — x86 uses ACPI/PCI, not device trees.
- **Hot-plug device discovery** — FDT is parsed once at boot. Runtime device changes handled by other mechanisms.
