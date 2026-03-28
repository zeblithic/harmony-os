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

Each sub-config holds MMIO base address, size, interrupt number, and `compatible` string. `MemoryRegion` stores base address and size in bytes (not page counts) to remain granule-agnostic. The struct lives in `harmony-microkernel` (Ring 2+ all consume it), and Ring 1 can also use it via dependency. `HardwareConfig` uses `Vec`, which requires `alloc` — this is available in all boot paths because boot stubs provide a global allocator (`LockedHeap` in aarch64, `linked_list_allocator` in x86_64) before constructing `HardwareConfig`.

**Population paths:**
- **FDT path (new):** Boot stub receives DTB pointer → `fdt` crate parses → populates `HardwareConfig`. FDT `reg` properties are already base+size in bytes.
- **UEFI path (existing):** Boot stub queries UEFI protocols → populates `HardwareConfig` from results + platform feature flags. Note: UEFI reports memory in 4KiB EFI pages regardless of OS page size; the population code converts to byte sizes (`efi_pages * 4096`).
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

**Descriptor address mask:** The current `ADDR_MASK = 0x0000_FFFF_FFFF_F000` extracts bits [47:12], which is 4K-specific. This must be generalized:

```rust
/// Mask for extracting the output address from a page table descriptor.
/// Bits [47:PAGE_SHIFT] — varies with granule.
pub const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_FFFF << PAGE_SHIFT >> PAGE_SHIFT << PAGE_SHIFT;
// 4K:  0x0000_FFFF_FFFF_F000 (bits [47:12])
// 16K: 0x0000_FFFF_FFFF_C000 (bits [47:14])
```

Or more readably: `!(PAGE_SIZE - 1) & 0x0000_FFFF_FFFF_FFFF`. Both `aarch64.rs` and `stage2.rs` currently hardcode this mask and must use the derived constant instead.

**Table entry array size:** The current `table_mut` returns `&mut [u64; 512]`. With 16K, tables have 2048 entries. Change to `&mut [u64]` slice (pointer + ENTRIES_PER_TABLE length) to avoid const-generic array sizes in the return type.

**Frame zeroing:** The current `aarch64.rs` has a hardcoded `write_bytes(new_ptr, 0, 4096)` when zeroing newly allocated intermediate page tables. This must become `write_bytes(new_ptr, 0, PAGE_SIZE as usize)` — partial zeroing on 16K would leave garbage entries that could be interpreted as valid descriptors.

**USER_SPACE_END:** The existing code uses `0x0000_7FFF_FFFF_F000` which is a 47-bit VA space (not 48-bit). This is correct for the current implementation and also sufficient for 16K (which also uses 47-bit VA). Generalize to: `(1u64 << (PAGE_SHIFT + TABLE_LEVELS as u32 * LEVEL_BITS)) - PAGE_SIZE`. This yields `(1 << 48) - 4096` for 4K (expanding to full 48-bit, correcting the current conservative limit) and `(1 << 47) - 16384` for 16K.

**TCR_EL1:** The boot stub's MMU setup sets granule bits: `TG0` = `0b00` (4K) or `0b10` (16K); `TG1` = `0b10` (4K) or `0b01` (16K). `T0SZ`/`T1SZ` must also change: `64 - VA_BITS` where VA_BITS is 48 (4K) or 47 (16K). Lives in the boot crate, not the microkernel.

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

impl Stage2Granule {
    pub const fn page_size(&self) -> u64 {
        match self { Self::Four => 4096, Self::Sixteen => 16384 }
    }
    pub const fn page_shift(&self) -> u32 {
        match self { Self::Four => 12, Self::Sixteen => 14 }
    }
    pub const fn level_bits(&self) -> u32 {
        match self { Self::Four => 9, Self::Sixteen => 11 }
    }
    pub const fn entries_per_table(&self) -> usize {
        match self { Self::Four => 512, Self::Sixteen => 2048 }
    }
    pub const fn start_level(&self) -> usize {
        match self { Self::Four => 0, Self::Sixteen => 1 }
    }
    pub const fn addr_mask(&self) -> u64 {
        match self {
            Self::Four => 0x0000_FFFF_FFFF_F000,
            Self::Sixteen => 0x0000_FFFF_FFFF_C000,
        }
    }
}

pub struct Stage2PageTable {
    granule: Stage2Granule,
    // ... existing fields
}
```

Stage-2 `map`/`unmap`/`index` use `self.granule` methods for all arithmetic — index extraction, address masking, frame zeroing size, and table level iteration. The current `Self::index()` hardcoded as `(ipa >> (12 + level * 9)) & 0x1FF` becomes `(ipa >> (self.granule.page_shift() + level as u32 * self.granule.level_bits())) & ((1 << self.granule.level_bits()) - 1)`.

**Intermediate table allocation:** When the host is 16K but the guest is 4K, the buddy allocator can only hand out 16K frames (one order-0 frame). A 4K guest page table uses only the first 4KiB of this 16K frame. The remaining 12KiB is zeroed and unused — wasteful but harmless and correct. Optimizing sub-page allocation is out of scope.

**Guest loader:** `guest_loader.rs` uses hardcoded `4096` for guest IPA layout computation. These remain hardcoded at 4K because the guest loader always prepares a 4K-granule guest image. If 16K guests are needed later, the guest loader can be parameterized.

Not hot-path — stage-2 mappings are set up at VM creation, not per-access.

**VTCR_EL2:** `TG0` set at VM creation to match the guest's granule. `T0SZ` set to `64 - guest_va_bits`.

### Linuxulator and ELF Loader Changes

**Linuxulator:** The local `const PAGE_SIZE: usize = 4096` at linuxulator.rs:1749 is replaced with an import from `harmony_microkernel::vm::PAGE_SIZE`. All existing mmap/brk/mprotect rounding logic already uses `PAGE_SIZE` — it just needs to come from the right source. On a 16K host, `sysconf(_SC_PAGESIZE)` returns 16384. No emulation, no sub-page tracking. Binaries requiring 4K pages use the hypervisor microVM path (Phase D+).

**ELF loader:** `elf_loader.rs` has its own `const PAGE_SIZE: u64 = 4096` (line 37) used for ELF segment alignment and the `AT_PAGESZ` auxiliary vector entry (line 370). Both must use the microkernel's `PAGE_SIZE`. On a 16K host, ELF segments are aligned to 16KiB boundaries and `AT_PAGESZ` reports 16384. ELF binaries compiled for 4K alignment will have their segments rounded up to 16K — the extra padding is zeroed and harmless for well-behaved binaries.

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
