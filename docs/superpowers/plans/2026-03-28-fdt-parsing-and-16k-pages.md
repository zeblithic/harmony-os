# FDT Parsing and 16KiB Page Granule Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add FDT device tree parsing and compile-time 16KiB page granule support for aarch64, enabling future Apple Silicon targets.

**Architecture:** A `page-16k` feature flag on `harmony-microkernel` switches `PAGE_SIZE`/`PAGE_SHIFT` at compile time. Aarch64 page table geometry (levels, index bits, entry count) adapts via a `geometry` module. FDT parsing is a boot-time module in `harmony-boot-aarch64` that produces a platform-agnostic `HardwareConfig` struct defined in the microkernel. Hypervisor stage-2 paging uses runtime granule selection for guests.

**Tech Stack:** Rust, `fdt` crate (no_std, zero-alloc), ARM64 page table specification (DDI 0487)

**Spec:** `docs/superpowers/specs/2026-03-28-fdt-parsing-and-16k-pages-design.md`

**Deferred to Phase D (harmony-os-5it):** TCR_EL1 granule bits (TG0/TG1/T0SZ/T1SZ) in boot stub MMU setup, and VTCR_EL2 configuration for stage-2 guest granule. These are hardware register changes that only matter when actually booting on a 16K target. The current boot stubs only target QEMU virt and RPi5 (both 4K). Phase D (m1n1 boot stub for Apple Silicon) is where TCR/VTCR configuration happens.

---

## File Structure

**Create:**
- `crates/harmony-microkernel/src/hardware_config.rs` — `HardwareConfig` and sub-config types
- `crates/harmony-boot-aarch64/src/fdt_parse.rs` — FDT-to-HardwareConfig conversion

**Modify:**
- `crates/harmony-microkernel/src/lib.rs` — add `pub mod hardware_config;`
- `crates/harmony-microkernel/Cargo.toml` — add `page-16k` feature
- `crates/harmony-microkernel/src/vm/mod.rs:14-18` — conditional PAGE_SIZE/PAGE_SHIFT
- `crates/harmony-microkernel/src/vm/aarch64.rs` — geometry module, generalize walk, ADDR_MASK, table_mut, write_bytes
- `crates/harmony-microkernel/src/vm/manager.rs:24` — derive USER_SPACE_END from constants
- `crates/harmony-hypervisor/src/stage2.rs` — Stage2Granule enum, runtime dispatch
- `crates/harmony-hypervisor/Cargo.toml` — `page-16k` passthrough feature
- `crates/harmony-os/src/linuxulator.rs:1749` — import PAGE_SIZE from microkernel
- `crates/harmony-os/src/elf_loader.rs:37` — import PAGE_SIZE from microkernel
- `crates/harmony-os/Cargo.toml` — `page-16k` passthrough feature
- `crates/harmony-boot-aarch64/Cargo.toml` — add `fdt` dependency

---

### Task 1: HardwareConfig Types

**Files:**
- Create: `crates/harmony-microkernel/src/hardware_config.rs`
- Modify: `crates/harmony-microkernel/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Add to the bottom of the new file `crates/harmony-microkernel/src/hardware_config.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardware_config_default_is_empty() {
        let cfg = HardwareConfig::default();
        assert!(cfg.memory_regions.is_empty());
        assert!(cfg.serial.is_none());
        assert!(cfg.interrupt_controller.is_none());
        assert!(cfg.network_devices.is_empty());
        assert!(cfg.block_devices.is_empty());
        assert_eq!(cfg.chosen.bootargs, None);
        assert_eq!(cfg.page_granule, 4096);
    }

    #[test]
    fn memory_region_stores_bytes() {
        let region = MemoryRegion {
            base: 0x4000_0000,
            size: 0x1_0000_0000, // 4 GiB
        };
        assert_eq!(region.size, 4 * 1024 * 1024 * 1024);
    }

    #[test]
    fn interrupt_controller_variant() {
        let gic = InterruptControllerConfig {
            base: 0x0800_0000,
            size: 0x1_0000,
            variant: InterruptControllerVariant::GicV3,
        };
        assert!(matches!(gic.variant, InterruptControllerVariant::GicV3));

        let aic = InterruptControllerConfig {
            base: 0x3B10_0000,
            size: 0xC000,
            variant: InterruptControllerVariant::AppleAic,
        };
        assert!(matches!(aic.variant, InterruptControllerVariant::AppleAic));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-microkernel hardware_config`
Expected: FAIL — module doesn't exist yet

- [ ] **Step 3: Write minimal implementation**

Create `crates/harmony-microkernel/src/hardware_config.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! Platform-agnostic hardware descriptor, populated at boot from FDT, UEFI,
//! or hardcoded constants depending on the boot path.

use alloc::string::String;
use alloc::vec::Vec;

/// A region of physical memory (base address and size in bytes).
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
}

/// UART serial console configuration.
#[derive(Debug, Clone)]
pub struct SerialConfig {
    pub base: u64,
    pub size: u64,
    pub compatible: String,
}

/// Interrupt controller type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterruptControllerVariant {
    GicV3,
    AppleAic,
}

/// Interrupt controller configuration.
#[derive(Debug, Clone)]
pub struct InterruptControllerConfig {
    pub base: u64,
    pub size: u64,
    pub variant: InterruptControllerVariant,
}

/// A network device discovered from the device tree.
#[derive(Debug, Clone)]
pub struct NetworkDeviceConfig {
    pub base: u64,
    pub size: u64,
    pub irq: u32,
    pub compatible: String,
}

/// A block storage device discovered from the device tree.
#[derive(Debug, Clone)]
pub struct BlockDeviceConfig {
    pub base: u64,
    pub size: u64,
    pub irq: u32,
    pub compatible: String,
}

/// Data from the /chosen device tree node.
#[derive(Debug, Clone, Default)]
pub struct ChosenConfig {
    pub bootargs: Option<String>,
    pub stdout_path: Option<String>,
    pub initrd_start: Option<u64>,
    pub initrd_end: Option<u64>,
}

/// Platform-agnostic hardware descriptor.
///
/// Populated at boot from FDT, UEFI, or hardcoded constants.
/// The runtime never knows which source was used.
#[derive(Debug, Clone)]
pub struct HardwareConfig {
    pub memory_regions: Vec<MemoryRegion>,
    pub serial: Option<SerialConfig>,
    pub interrupt_controller: Option<InterruptControllerConfig>,
    pub network_devices: Vec<NetworkDeviceConfig>,
    pub block_devices: Vec<BlockDeviceConfig>,
    pub chosen: ChosenConfig,
    /// Page granule reported by firmware/platform (4096 or 16384).
    pub page_granule: usize,
}

impl Default for HardwareConfig {
    fn default() -> Self {
        Self {
            memory_regions: Vec::new(),
            serial: None,
            interrupt_controller: None,
            network_devices: Vec::new(),
            block_devices: Vec::new(),
            chosen: ChosenConfig::default(),
            page_granule: 4096,
        }
    }
}
```

Add to `crates/harmony-microkernel/src/lib.rs`:

```rust
pub mod hardware_config;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-microkernel hardware_config`
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/hardware_config.rs crates/harmony-microkernel/src/lib.rs
git commit -m "feat(microkernel): add HardwareConfig platform descriptor types"
```

---

### Task 2: page-16k Feature Flag and Conditional Constants

**Files:**
- Modify: `crates/harmony-microkernel/Cargo.toml`
- Modify: `crates/harmony-microkernel/src/vm/mod.rs:14-18`
- Modify: `crates/harmony-microkernel/src/vm/aarch64.rs:1-25` (doc comment only)

- [ ] **Step 1: Write the failing test**

Add to the existing `tests` module at the bottom of `crates/harmony-microkernel/src/vm/mod.rs`:

```rust
    #[test]
    fn page_constants_consistent() {
        assert_eq!(PAGE_SIZE, 1u64 << PAGE_SHIFT);
        assert!(PAGE_SIZE.is_power_of_two());
        assert!(PAGE_SIZE >= 4096);
    }
```

- [ ] **Step 2: Run test to verify it passes with default features (sanity check)**

Run: `cargo test -p harmony-microkernel page_constants_consistent`
Expected: PASS (4096 == 1 << 12)

- [ ] **Step 3: Add `page-16k` feature to Cargo.toml**

In `crates/harmony-microkernel/Cargo.toml`, add after the `kernel` feature:

```toml
# 16 KiB page granule for aarch64 targets (Apple Silicon, etc.).
# Switches PAGE_SIZE from 4096 to 16384 at compile time.
page-16k = []
```

- [ ] **Step 4: Make PAGE_SIZE and PAGE_SHIFT conditional**

In `crates/harmony-microkernel/src/vm/mod.rs`, replace lines 14-18:

```rust
/// Page size in bytes (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

/// Number of bits to shift for page-frame alignment.
pub const PAGE_SHIFT: u32 = 12;
```

with:

```rust
/// Page size in bytes.
#[cfg(not(feature = "page-16k"))]
pub const PAGE_SIZE: u64 = 4096;

/// Page size in bytes.
#[cfg(feature = "page-16k")]
pub const PAGE_SIZE: u64 = 16384;

/// Number of bits to shift for page-frame alignment.
#[cfg(not(feature = "page-16k"))]
pub const PAGE_SHIFT: u32 = 12;

/// Number of bits to shift for page-frame alignment.
#[cfg(feature = "page-16k")]
pub const PAGE_SHIFT: u32 = 14;
```

- [ ] **Step 5: Run tests with both feature configurations**

Run: `cargo test -p harmony-microkernel page_constants_consistent`
Expected: PASS (4096)

Run: `cargo test -p harmony-microkernel --features page-16k page_constants_consistent`
Expected: PASS (16384)

- [ ] **Step 6: Verify address alignment helpers adapt**

The `VirtAddr::page_align_up/down` and `PhysAddr::page_align_up/down` methods already use `PAGE_SIZE`, so they'll align to 16K automatically. Run existing tests:

Run: `cargo test -p harmony-microkernel --features page-16k virt_addr_page_align`
Expected: FAIL — test asserts `VirtAddr(4097).page_align_down() == VirtAddr(4096)`, but with 16K pages, align_down(4097) == 0. This test is 4K-specific.

- [ ] **Step 7: Gate the 4K-specific address alignment tests**

In `crates/harmony-microkernel/src/vm/mod.rs`, add `#[cfg(not(feature = "page-16k"))]` before the `virt_addr_page_align` and `phys_addr_page_align` tests, and add new granule-agnostic tests:

```rust
    #[cfg(not(feature = "page-16k"))]
    #[test]
    fn virt_addr_page_align() {
        // ... existing test unchanged ...
    }

    #[cfg(not(feature = "page-16k"))]
    #[test]
    fn phys_addr_page_align() {
        // ... existing test unchanged ...
    }

    #[test]
    fn virt_addr_page_align_generic() {
        let page = PAGE_SIZE;
        let addr = VirtAddr(page + 1);
        assert_eq!(addr.page_align_down(), VirtAddr(page));
        assert_eq!(addr.page_align_up(), VirtAddr(page * 2));
        assert!(!addr.is_page_aligned());

        let aligned = VirtAddr(page);
        assert!(aligned.is_page_aligned());
        assert_eq!(aligned.page_align_down(), aligned);
        assert_eq!(aligned.page_align_up(), aligned);
    }

    #[test]
    fn phys_addr_page_align_generic() {
        let page = PAGE_SIZE;
        let addr = PhysAddr(page + 1);
        assert_eq!(addr.page_align_down(), PhysAddr(page));
        assert_eq!(addr.page_align_up(), PhysAddr(page * 2));
        assert!(!addr.is_page_aligned());

        let aligned = PhysAddr(page);
        assert!(aligned.is_page_aligned());
        assert_eq!(aligned.page_align_down(), aligned);
        assert_eq!(aligned.page_align_up(), aligned);
    }
```

- [ ] **Step 8: Run all vm tests with both features**

Run: `cargo test -p harmony-microkernel --features page-16k -- vm::tests`
Expected: PASS

Run: `cargo test -p harmony-microkernel -- vm::tests`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add crates/harmony-microkernel/Cargo.toml crates/harmony-microkernel/src/vm/mod.rs
git commit -m "feat(microkernel): add page-16k feature flag with conditional PAGE_SIZE/PAGE_SHIFT"
```

---

### Task 3: Generalize Aarch64 Page Table Geometry

**Files:**
- Modify: `crates/harmony-microkernel/src/vm/aarch64.rs`

This is the largest task. The page table walk, index extraction, ADDR_MASK, table_mut, and frame zeroing all need to adapt.

- [ ] **Step 1: Write failing test for 16K geometry**

Add to the existing `tests` module in `crates/harmony-microkernel/src/vm/aarch64.rs`:

```rust
    /// Verify that geometry constants are consistent with PAGE_SIZE.
    #[test]
    fn geometry_constants_consistent() {
        use super::geometry::*;
        use super::super::{PAGE_SHIFT, PAGE_SIZE};
        // Table must fit in one page.
        assert_eq!(ENTRIES_PER_TABLE * 8, PAGE_SIZE as usize);
        // VA bits = PAGE_SHIFT + TABLE_LEVELS * LEVEL_BITS.
        let va_bits = PAGE_SHIFT + TABLE_LEVELS as u32 * LEVEL_BITS;
        assert!(va_bits == 47 || va_bits == 48);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-microkernel geometry_constants_consistent`
Expected: FAIL — `geometry` module doesn't exist yet

- [ ] **Step 3: Add geometry module and generalize constants**

At the top of `crates/harmony-microkernel/src/vm/aarch64.rs`, after the descriptor bit constants and before the `Aarch64PageTable` struct, add:

```rust
// ── Page table geometry ─────────────────────────────────────────────

use super::{PAGE_SHIFT, PAGE_SIZE};

/// Geometry constants for the aarch64 translation table.
/// 4 KiB granule: 4 levels (L0→L3), 512 entries, 9-bit index, 48-bit VA.
/// 16 KiB granule: 3 levels (L1→L3), 2048 entries, 11-bit index, 47-bit VA.
#[cfg(not(feature = "page-16k"))]
pub(crate) mod geometry {
    pub const ENTRIES_PER_TABLE: usize = 512;
    pub const LEVEL_BITS: u32 = 9;
    pub const TABLE_LEVELS: usize = 4;
    pub const START_LEVEL: usize = 0;
    /// Highest level index used in the walk (L0 for 4K).
    pub const MAX_LEVEL: usize = 3;
}

#[cfg(feature = "page-16k")]
pub(crate) mod geometry {
    pub const ENTRIES_PER_TABLE: usize = 2048;
    pub const LEVEL_BITS: u32 = 11;
    pub const TABLE_LEVELS: usize = 3;
    pub const START_LEVEL: usize = 1;
    /// Highest level index used in the walk (L1 for 16K — L0 unused).
    pub const MAX_LEVEL: usize = 3;
}

/// Mask for extracting the output address from a descriptor.
/// Clears page offset bits [PAGE_SHIFT-1:0] and reserved bits [63:48].
const ADDR_MASK: u64 = !(PAGE_SIZE - 1) & 0x0000_FFFF_FFFF_FFFF;

/// Index mask: (1 << LEVEL_BITS) - 1.
const INDEX_MASK: u64 = (1u64 << geometry::LEVEL_BITS) - 1;

// Compile-time guard: page-16k is only valid on aarch64.
#[cfg(all(feature = "page-16k", not(target_arch = "aarch64")))]
compile_error!("page-16k feature is only supported on aarch64 targets");
```

Remove the old hardcoded `ADDR_MASK`:
```rust
// DELETE THIS LINE:
// const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;
```

- [ ] **Step 4: Generalize `index()` function**

Replace the current `index` method (line 131-133):

```rust
    fn index(vaddr: VirtAddr, level: usize) -> usize {
        ((vaddr.as_u64() >> (PAGE_SHIFT + level as u32 * geometry::LEVEL_BITS)) & INDEX_MASK)
            as usize
    }
```

Update the doc comment to remove hardcoded bit ranges.

- [ ] **Step 5: Generalize `table_mut()` to return a slice**

Replace `table_mut` (line 120-123):

```rust
    fn table_mut(&self, table_paddr: PhysAddr) -> &mut [u64] {
        let ptr = (self.phys_to_virt)(table_paddr) as *mut u64;
        unsafe { core::slice::from_raw_parts_mut(ptr, geometry::ENTRIES_PER_TABLE) }
    }
```

- [ ] **Step 6: Generalize `is_table_empty()` to accept a slice**

Replace `is_table_empty` (line 215-217):

```rust
    fn is_table_empty(table: &[u64]) -> bool {
        table.iter().all(|&e| !Self::is_valid(e))
    }
```

- [ ] **Step 7: Generalize walk loops in `map`, `unmap`, `set_flags`, `translate`**

The pattern `for level in (1..=3).rev()` becomes `for level in (geometry::START_LEVEL..=geometry::MAX_LEVEL).rev().skip(1)` — wait, let me be precise. The current code walks levels 3→1 for intermediates, then uses level 0 for the leaf.

With the geometry module: walk levels `MAX_LEVEL` down to `START_LEVEL + 1` for intermediates, then `START_LEVEL` for the leaf.

In `map()`, replace `for level in (1..=3).rev()` with:

```rust
        for level in ((geometry::START_LEVEL + 1)..=geometry::MAX_LEVEL).rev() {
```

In the `write_bytes` call inside `map()`, replace the hardcoded `4096`:

```rust
                    core::ptr::write_bytes(new_ptr, 0, PAGE_SIZE as usize);
```

In `unmap()`, replace `for level in (1..=3).rev()` and `let mut walk: [(PhysAddr, usize); 3]`:

```rust
        let intermediate_levels = geometry::MAX_LEVEL - geometry::START_LEVEL;
        let mut walk = alloc::vec![(PhysAddr(0), 0usize); intermediate_levels];

        for (i, level) in ((geometry::START_LEVEL + 1)..=geometry::MAX_LEVEL).rev().enumerate() {
```

And the leaf level: replace `Self::index(vaddr, 0)` with `Self::index(vaddr, geometry::START_LEVEL)`.

In `set_flags()`, replace `for level in (1..=3).rev()` and `Self::index(vaddr, 0)` similarly.

In `translate()`, replace `for level in (1..=3).rev()` and `Self::index(vaddr, 0)` similarly.

- [ ] **Step 8: Update the doc comment at the top of aarch64.rs**

Replace the hardcoded doc table (lines 2-14) with:

```rust
//! aarch64 translation table implementation.
//!
//! Provides `Aarch64PageTable`, a concrete [`PageTable`] implementation
//! for aarch64. The page table geometry adapts to the page granule:
//!
//! - 4 KiB granule (default): 4 levels (L0→L3), 512 entries, 9-bit index, 48-bit VA
//! - 16 KiB granule (`page-16k`): 3 levels (L1→L3), 2048 entries, 11-bit index, 47-bit VA
```

- [ ] **Step 9: Update the `new()` doc comment**

Change "4 KiB-aligned frame" to "PAGE_SIZE-aligned frame" in the safety comment.

- [ ] **Step 10: Run existing tests with default (4K) features**

Run: `cargo test -p harmony-microkernel -- aarch64::tests`
Expected: ALL PASS — behavior unchanged for 4K

- [ ] **Step 11: Gate 4K-specific test constants and add generic versions**

In the test module, the arena sizing uses hardcoded `4096`:

```rust
    const ARENA_SIZE: usize = ARENA_TABLES * 4096;
```

Replace with:

```rust
    const ARENA_SIZE: usize = ARENA_TABLES * PAGE_SIZE as usize;
```

Similarly, `TestAllocator::new` uses `4096` for frame advancement:

```rust
    impl TestAllocator {
        fn new(base: u64, count: usize) -> Self {
            Self {
                next: base,
                limit: base + (count as u64) * PAGE_SIZE,
            }
        }

        fn alloc(&mut self) -> Option<PhysAddr> {
            if self.next >= self.limit {
                return None;
            }
            let addr = PhysAddr(self.next);
            self.next += PAGE_SIZE;
            Some(addr)
        }
    }
```

And `TrackingAllocator` similarly. Also, all `write_bytes(..., 0, 4096)` in tests should become `write_bytes(..., 0, PAGE_SIZE as usize)`.

Arena allocation alignment: `(base + 4095) & !4095` should become `(base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)`.

Extra arena headroom: `ARENA_SIZE + 4096` should become `ARENA_SIZE + PAGE_SIZE as usize`.

The `index_extraction` test asserts 4K-specific bit positions. Gate it with `#[cfg(not(feature = "page-16k"))]` and add a 16K variant:

```rust
    #[cfg(feature = "page-16k")]
    #[test]
    fn index_extraction_16k() {
        // 16K granule: 3 levels (L1→L3), 11-bit index
        // L3 (level 3): bits [46:36]
        // L2 (level 2): bits [35:25]
        // L1 (level 1): bits [24:14]
        let va = VirtAddr((1u64 << 36) | (2u64 << 25) | (3u64 << 14));
        assert_eq!(Aarch64PageTable::index(va, 3), 1, "L3 index");
        assert_eq!(Aarch64PageTable::index(va, 2), 2, "L2 index");
        assert_eq!(Aarch64PageTable::index(va, 1), 3, "L1 index");
    }
```

The `unmap_prunes_empty_intermediate` test asserts 3 intermediates. With 16K (3-level), there are only 2 intermediates. Gate it and add 16K version:

```rust
    #[cfg(not(feature = "page-16k"))]
    #[test]
    fn unmap_prunes_empty_intermediate() {
        // ... existing test (expects 3 intermediates) ...
    }

    #[cfg(feature = "page-16k")]
    #[test]
    fn unmap_prunes_empty_intermediate_16k() {
        // Same as above but expects 2 intermediates (3-level walk)
        // ... allocator setup same ...
        let intermediates_allocated = alloc.alloc_count;
        assert_eq!(intermediates_allocated, 2, "16K mapping needs 2 intermediate tables");
        // ... unmap, check 2 freed ...
    }
```

- [ ] **Step 12: Add 16K-specific geometry test**

```rust
    #[cfg(feature = "page-16k")]
    #[test]
    fn page_table_47bit_va_limit() {
        use super::super::PAGE_SIZE;
        let (_arena, arena_base) = test_arena();
        let aligned = (arena_base.as_u64() + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let root = PhysAddr(aligned);
        unsafe { core::ptr::write_bytes(root.as_u64() as *mut u8, 0, PAGE_SIZE as usize) };
        let mut allocator = TestAllocator::new(aligned + PAGE_SIZE, ARENA_TABLES - 1);
        let mut pt = unsafe { Aarch64PageTable::new(root, identity_phys_to_virt) };

        // Map at the highest valid 47-bit VA.
        let max_va = VirtAddr((1u64 << 47) - PAGE_SIZE);
        let paddr = PhysAddr(0xBEEF_0000u64 & !(PAGE_SIZE - 1));
        let flags = PageFlags::READABLE;
        let result = pt.map(max_va, paddr, flags, &mut || allocator.alloc());
        assert!(result.is_ok(), "should map at 47-bit VA boundary");
        let (got_paddr, _) = pt.translate(max_va).unwrap();
        assert_eq!(got_paddr, paddr);
    }
```

- [ ] **Step 13: Run all aarch64 tests with both features**

Run: `cargo test -p harmony-microkernel -- aarch64::tests`
Expected: ALL PASS (4K)

Run: `cargo test -p harmony-microkernel --features page-16k -- aarch64::tests`
Expected: ALL PASS (16K)

- [ ] **Step 14: Commit**

```bash
git add crates/harmony-microkernel/src/vm/aarch64.rs
git commit -m "feat(microkernel): generalize aarch64 page table for 4K/16K granule"
```

---

### Task 4: Derive USER_SPACE_END from Geometry

**Files:**
- Modify: `crates/harmony-microkernel/src/vm/manager.rs:24`

- [ ] **Step 1: Write failing test**

Add to the test module in `crates/harmony-microkernel/src/vm/manager.rs` (or if none exists, check for existing tests and add near them):

```rust
    #[test]
    fn user_space_end_consistent_with_geometry() {
        use super::super::{PAGE_SHIFT, PAGE_SIZE};
        // USER_SPACE_END must be below the maximum VA for the current granule.
        assert!(USER_SPACE_END < (1u64 << 48));
        assert!(USER_SPACE_END > 0);
        // Must be page-aligned.
        assert_eq!(USER_SPACE_END & (PAGE_SIZE - 1), 0);
    }
```

- [ ] **Step 2: Run test — verify it passes (sanity check on current value)**

Run: `cargo test -p harmony-microkernel user_space_end_consistent`
Expected: PASS

- [ ] **Step 3: Replace hardcoded USER_SPACE_END**

In `crates/harmony-microkernel/src/vm/manager.rs`, replace line 24:

```rust
const USER_SPACE_END: u64 = 0x0000_7FFF_FFFF_F000;
```

with separate `#[cfg]`-gated constants (Rust does not support `#[cfg]` inside `const` blocks on stable):

```rust
/// End of user-space VA range. Derived from page table geometry.
/// aarch64 4K: 48-bit VA → (1 << 48) - 4096
/// aarch64 16K: 47-bit VA → (1 << 47) - 16384
/// x86_64: always 48-bit VA → (1 << 48) - 4096
#[cfg(all(target_arch = "aarch64", not(feature = "page-16k")))]
const USER_SPACE_END: u64 = (1u64 << 48) - 4096;
#[cfg(all(target_arch = "aarch64", feature = "page-16k"))]
const USER_SPACE_END: u64 = (1u64 << 47) - 16384;
#[cfg(target_arch = "x86_64")]
const USER_SPACE_END: u64 = (1u64 << 48) - 4096;
// Test host on macOS aarch64 matches the aarch64 path above.
// This fallback covers other architectures (e.g. wasm32 for testing).
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
const USER_SPACE_END: u64 = (1u64 << 47) - 4096;
```

- [ ] **Step 4: Run tests with both features**

Run: `cargo test -p harmony-microkernel user_space_end`
Expected: PASS

Run: `cargo test -p harmony-microkernel --features page-16k user_space_end`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/vm/manager.rs
git commit -m "feat(microkernel): derive USER_SPACE_END from page table geometry"
```

---

### Task 5: Stage2Granule Runtime Dispatch

**Files:**
- Modify: `crates/harmony-hypervisor/src/stage2.rs`
- Modify: `crates/harmony-hypervisor/Cargo.toml`

- [ ] **Step 1: Write failing test**

Add to the test module in `crates/harmony-hypervisor/src/stage2.rs` (if tests exist) or create one:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage2_granule_four_geometry() {
        let g = Stage2Granule::Four;
        assert_eq!(g.page_size(), 4096);
        assert_eq!(g.page_shift(), 12);
        assert_eq!(g.level_bits(), 9);
        assert_eq!(g.entries_per_table(), 512);
        assert_eq!(g.start_level(), 0);
        assert_eq!(g.addr_mask(), 0x0000_FFFF_FFFF_F000);
    }

    #[test]
    fn stage2_granule_sixteen_geometry() {
        let g = Stage2Granule::Sixteen;
        assert_eq!(g.page_size(), 16384);
        assert_eq!(g.page_shift(), 14);
        assert_eq!(g.level_bits(), 11);
        assert_eq!(g.entries_per_table(), 2048);
        assert_eq!(g.start_level(), 1);
        assert_eq!(g.addr_mask(), 0x0000_FFFF_FFFF_C000);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-hypervisor stage2_granule`
Expected: FAIL — `Stage2Granule` doesn't exist

- [ ] **Step 3: Add Stage2Granule enum and methods**

In `crates/harmony-hypervisor/src/stage2.rs`, add before the `Stage2PageTable` struct:

```rust
/// Runtime page granule selection for guest stage-2 mappings.
/// The host is compiled for a fixed granule, but guests may use a different one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage2Granule {
    /// 4 KiB pages: 4-level, 512 entries, 9-bit index.
    Four,
    /// 16 KiB pages: 3-level, 2048 entries, 11-bit index.
    Sixteen,
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
    pub const fn max_level(&self) -> usize {
        3 // Both granules use level 3 as the highest
    }
}
```

- [ ] **Step 4: Add `granule` field to `Stage2PageTable` and update constructor**

Add `granule: Stage2Granule` to the struct and constructor. Default to `Stage2Granule::Four` for backward compatibility:

```rust
pub struct Stage2PageTable {
    root: PhysAddr,
    vmid: VmId,
    granule: Stage2Granule,
    phys_to_virt: fn(PhysAddr) -> *mut u8,
    owned_frames: alloc::vec::Vec<PhysAddr>,
}
```

Add `granule` parameter to `new()`:

```rust
    pub fn new(
        root: PhysAddr,
        vmid: VmId,
        granule: Stage2Granule,
        phys_to_virt: fn(PhysAddr) -> *mut u8,
    ) -> Self {
        Self { root, vmid, granule, phys_to_virt, owned_frames: alloc::vec![root] }
    }
```

- [ ] **Step 5: Replace hardcoded ADDR_MASK and index function**

Remove the file-level `const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;`.

Replace `Self::index(ipa, level)` with a method that uses the granule:

```rust
    fn index(&self, ipa: u64, level: usize) -> usize {
        ((ipa >> (self.granule.page_shift() + level as u32 * self.granule.level_bits()))
            & ((1u64 << self.granule.level_bits()) - 1)) as usize
    }
```

In all methods (`map`, `unmap`, `walk`), replace:
- `Self::index(ipa, level)` → `self.index(ipa, level)`
- `& ADDR_MASK` → `& self.granule.addr_mask()`
- `(PAGE_SIZE - 1)` for alignment checks → `(self.granule.page_size() - 1)`
- `for level in (1..=3).rev()` → `for level in ((self.granule.start_level() + 1)..=self.granule.max_level()).rev()`
- Leaf level `Self::index(ipa, 0)` → `self.index(ipa, self.granule.start_level())`

**Keep** `write_bytes(new_ptr, 0, PAGE_SIZE as usize)` using the **host** `PAGE_SIZE` (imported from `harmony_microkernel::vm`), NOT `self.granule.page_size()`. The buddy allocator hands out host-sized frames regardless of guest granule. A 4K guest table in a 16K host frame uses only the first 4K — the rest is zeroed and unused but the entire frame must be clean.

- [ ] **Step 6: Update all call sites of `Stage2PageTable::new()`**

Search the codebase for `Stage2PageTable::new(` and add the `Stage2Granule::Four` parameter. This is likely in:
- `crates/harmony-hypervisor/src/hypervisor.rs` (HVC handler for VM creation)
- Test code

- [ ] **Step 7: Run all hypervisor tests**

Run: `cargo test -p harmony-hypervisor`
Expected: ALL PASS

- [ ] **Step 8: Add `page-16k` feature passthrough to hypervisor Cargo.toml**

In `crates/harmony-hypervisor/Cargo.toml`:

```toml
[features]
default = []
page-16k = ["harmony-microkernel/page-16k"]
```

- [ ] **Step 9: Commit**

```bash
git add crates/harmony-hypervisor/src/stage2.rs crates/harmony-hypervisor/Cargo.toml
git commit -m "feat(hypervisor): add Stage2Granule for runtime guest page size selection"
```

---

### Task 6: Fix Linuxulator and ELF Loader PAGE_SIZE

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs:1749`
- Modify: `crates/harmony-os/src/elf_loader.rs:37`
- Modify: `crates/harmony-os/Cargo.toml`

- [ ] **Step 1: Write failing test**

In `crates/harmony-os/src/elf_loader.rs`, find the test module and add:

```rust
    #[test]
    fn page_size_matches_microkernel() {
        assert_eq!(
            PAGE_SIZE,
            harmony_microkernel::vm::PAGE_SIZE as u64,
            "elf_loader PAGE_SIZE must match microkernel"
        );
    }
```

- [ ] **Step 2: Run test — it should pass currently (both are 4096), but it ensures the import works**

Run: `cargo test -p harmony-os page_size_matches`
Expected: PASS (verifying setup)

- [ ] **Step 3: Replace local PAGE_SIZE in elf_loader.rs**

In `crates/harmony-os/src/elf_loader.rs`, replace line 37:

```rust
const PAGE_SIZE: u64 = 4096;
```

with:

```rust
use harmony_microkernel::vm::PAGE_SIZE;
```

- [ ] **Step 4: Replace local PAGE_SIZE in linuxulator.rs**

In `crates/harmony-os/src/linuxulator.rs`, replace line 1749:

```rust
const PAGE_SIZE: usize = 4096;
```

with:

```rust
const PAGE_SIZE: usize = harmony_microkernel::vm::PAGE_SIZE as usize;
```

(Using `const` assignment from the `u64` constant to `usize` to avoid changing all usage sites from `usize` to `u64`.)

- [ ] **Step 5: Add `page-16k` feature passthrough to harmony-os Cargo.toml**

In `crates/harmony-os/Cargo.toml`, add:

```toml
page-16k = ["harmony-microkernel/page-16k"]
```

(Add to the `[features]` section after `std`.)

- [ ] **Step 6: Gate 4K-specific ELF loader and linuxulator tests**

The ELF loader tests contain many hardcoded `4096` and `assert_eq!(at_pagesz, 4096, ...)` assertions. These will fail under `page-16k`. Search for all test functions in `elf_loader.rs` and `linuxulator.rs` that assert specific page sizes or 4K-aligned addresses. Gate them with `#[cfg(not(feature = "page-16k"))]`.

Specifically, in `crates/harmony-os/src/elf_loader.rs` tests:
- Any test asserting `AT_PAGESZ == 4096` → gate with `#[cfg(not(feature = "page-16k"))]`
- Any test asserting page-aligned addresses using literal 4096 → either gate or update to use `PAGE_SIZE`

Do the same for `crates/harmony-os/src/linuxulator.rs` tests that use hardcoded `4096`.

For key assertions, add 16K-aware variants:

```rust
#[cfg(feature = "page-16k")]
#[test]
fn at_pagesz_reports_16k() {
    // Same test setup as the 4K variant, but assert AT_PAGESZ == 16384
}
```

- [ ] **Step 7: Run tests with both features**

Run: `cargo test -p harmony-os`
Expected: PASS (default 4K)

Run: `cargo test -p harmony-os --features page-16k`
Expected: PASS (16K, gated tests skipped)

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs crates/harmony-os/src/elf_loader.rs crates/harmony-os/Cargo.toml
git commit -m "fix(os): import PAGE_SIZE from microkernel, gate 4K-specific tests"
```

---

### Task 7: FDT Parsing Module

**Files:**
- Create: `crates/harmony-boot-aarch64/src/fdt_parse.rs`
- Modify: `crates/harmony-boot-aarch64/Cargo.toml`
- Modify: `crates/harmony-boot-aarch64/src/main.rs` (add `mod fdt_parse;`)

Note: `harmony-boot-aarch64` is excluded from the workspace (bare-metal target). It has its own `[workspace]` table and cannot be tested via `cargo test -p`. Tests for FDT parsing must be added as unit tests within the module and compiled when `cfg(test)` — which requires a host-target build. To make this testable, we add the FDT parsing logic as a separate module with `#[cfg(test)]` tests that work on the host. The `fdt` crate is `no_std` and works on host targets too.

**Alternative approach for testability:** Since the boot crate can't be tested in the workspace, put the parsing tests in `harmony-microkernel` (which CAN be workspace-tested) behind a `dev-dependency` on the `fdt` crate. The actual `fdt_parse` module in the boot crate is thin glue; the test lives where it can actually run.

- [ ] **Step 1: Add `fdt` dependency to harmony-boot-aarch64**

In `crates/harmony-boot-aarch64/Cargo.toml`, add to `[dependencies]`:

```toml
fdt = { version = "0.2", default-features = false }
```

- [ ] **Step 2: Create fdt_parse.rs with the parsing function**

Create `crates/harmony-boot-aarch64/src/fdt_parse.rs`:

```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! FDT (Flattened Device Tree) parsing → HardwareConfig conversion.
//!
//! Takes a raw DTB blob pointer and produces a `HardwareConfig` populated
//! with the hardware discovered from the device tree. This is boot-time glue
//! code — not a general-purpose FDT abstraction.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use harmony_microkernel::hardware_config::*;

/// Parse a Flattened Device Tree blob into a `HardwareConfig`.
///
/// # Safety
///
/// `dtb_ptr` must point to a valid FDT blob that remains readable for the
/// duration of this call.
///
/// # Panics
///
/// Panics if no `/memory` node is found (cannot boot without RAM).
pub unsafe fn parse_fdt(dtb_ptr: *const u8) -> HardwareConfig {
    let fdt = fdt::Fdt::from_ptr(dtb_ptr).expect("invalid FDT blob");
    let mut config = HardwareConfig::default();

    // ── Memory regions ──────────────────────────────────────────────
    let mut found_memory = false;
    for node in fdt.all_nodes() {
        if node.name.starts_with("memory") {
            if let Some(reg) = node.reg() {
                for region in reg {
                    config.memory_regions.push(MemoryRegion {
                        base: region.starting_address as u64,
                        size: region.size.unwrap_or(0) as u64,
                    });
                    found_memory = true;
                }
            }
        }
    }
    assert!(found_memory, "FDT: no /memory node found — cannot boot");

    // ── /chosen ──────────────────────────────────────────────────────
    if let Some(chosen) = fdt.chosen() {
        config.chosen.bootargs = chosen.bootargs().map(|s| s.to_string());
        config.chosen.stdout_path = chosen.stdout().map(|n| n.name.to_string());
    }

    // ── Peripheral discovery by compatible string ────────────────────
    for node in fdt.all_nodes() {
        let compat_list: Vec<&str> = node
            .compatible()
            .map(|c| c.all().collect())
            .unwrap_or_default();

        for compat in &compat_list {
            match *compat {
                // Serial
                "arm,pl011" | "apple,uart" => {
                    if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                        config.serial = Some(SerialConfig {
                            base: reg.starting_address as u64,
                            size: reg.size.unwrap_or(0x1000) as u64,
                            compatible: compat.to_string(),
                        });
                    }
                }

                // Interrupt controller
                "arm,gic-v3" | "arm,cortex-a15-gic" => {
                    if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                        config.interrupt_controller = Some(InterruptControllerConfig {
                            base: reg.starting_address as u64,
                            size: reg.size.unwrap_or(0x10000) as u64,
                            variant: InterruptControllerVariant::GicV3,
                        });
                    }
                }
                "apple,aic" | "apple,aic2" => {
                    if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                        config.interrupt_controller = Some(InterruptControllerConfig {
                            base: reg.starting_address as u64,
                            size: reg.size.unwrap_or(0xC000) as u64,
                            variant: InterruptControllerVariant::AppleAic,
                        });
                    }
                }

                // Network devices
                "virtio,mmio" => {
                    if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                        config.network_devices.push(NetworkDeviceConfig {
                            base: reg.starting_address as u64,
                            size: reg.size.unwrap_or(0x200) as u64,
                            irq: first_irq(&node),
                            compatible: compat.to_string(),
                        });
                    }
                }

                // Block devices
                "nvme" | "apple,ans2" => {
                    if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                        config.block_devices.push(BlockDeviceConfig {
                            base: reg.starting_address as u64,
                            size: reg.size.unwrap_or(0x40000) as u64,
                            irq: first_irq(&node),
                            compatible: compat.to_string(),
                        });
                    }
                }

                _ => {} // Unknown compatible — ignore
            }
        }
    }

    config
}

/// Extract the first interrupt number from a node's `interrupts` property.
/// Returns 0 if no interrupt property exists.
fn first_irq(node: &fdt::node::FdtNode) -> u32 {
    node.property("interrupts")
        .and_then(|p| {
            let bytes = p.value;
            if bytes.len() >= 4 {
                Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            } else {
                None
            }
        })
        .unwrap_or(0)
}
```

- [ ] **Step 3: Add `mod fdt_parse;` to the boot crate's main.rs**

In `crates/harmony-boot-aarch64/src/main.rs`, add:

```rust
mod fdt_parse;
```

- [ ] **Step 4: Write FDT parsing tests in harmony-microkernel**

Since the boot crate is excluded from workspace, duplicate the core parsing logic as a testable function in `crates/harmony-microkernel/src/hardware_config.rs`. Add `fdt` as a dev-dependency:

In `crates/harmony-microkernel/Cargo.toml`:

```toml
[dev-dependencies]
# ... existing ...
fdt = "0.2"
```

Add a `#[cfg(test)]` parsing function and tests to `crates/harmony-microkernel/src/hardware_config.rs`:

```rust
    /// Parse a DTB blob into HardwareConfig (test-only, mirrors fdt_parse.rs logic).
    #[cfg(test)]
    fn parse_fdt_for_test(dtb: &[u8]) -> HardwareConfig {
        let fdt = fdt::Fdt::new(dtb).expect("invalid FDT");
        let mut config = HardwareConfig::default();

        for node in fdt.all_nodes() {
            if node.name.starts_with("memory") {
                if let Some(reg) = node.reg() {
                    for region in reg {
                        config.memory_regions.push(MemoryRegion {
                            base: region.starting_address as u64,
                            size: region.size.unwrap_or(0) as u64,
                        });
                    }
                }
            }
        }

        if let Some(chosen) = fdt.chosen() {
            config.chosen.bootargs = chosen.bootargs().map(|s| s.to_string());
        }

        for node in fdt.all_nodes() {
            if let Some(compat) = node.compatible() {
                for c in compat.all() {
                    match c {
                        "arm,pl011" => {
                            if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                                config.serial = Some(SerialConfig {
                                    base: reg.starting_address as u64,
                                    size: reg.size.unwrap_or(0x1000) as u64,
                                    compatible: c.to_string(),
                                });
                            }
                        }
                        "arm,gic-v3" => {
                            if let Some(reg) = node.reg().and_then(|mut r| r.next()) {
                                config.interrupt_controller =
                                    Some(InterruptControllerConfig {
                                        base: reg.starting_address as u64,
                                        size: reg.size.unwrap_or(0x10000) as u64,
                                        variant: InterruptControllerVariant::GicV3,
                                    });
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        config
    }
```

To test this, dump a QEMU virt DTB (one-time):
```bash
qemu-system-aarch64 -machine virt,dumpdtb=/tmp/qemu-virt.dtb -cpu cortex-a57 2>/dev/null
xxd -i /tmp/qemu-virt.dtb > /tmp/qemu_virt_dtb.txt
```

Alternatively, use the `fdt` crate's DTB builder or embed a minimal synthetic DTB as a `&[u8]` constant. The simplest approach for CI-reproducible tests: include a small QEMU-generated DTB as a test fixture file at `crates/harmony-microkernel/tests/fixtures/qemu-virt.dtb`.

Add tests:

```rust
    #[test]
    fn fdt_parse_qemu_virt() {
        let dtb = include_bytes!("../tests/fixtures/qemu-virt.dtb");
        let cfg = parse_fdt_for_test(dtb);
        assert!(!cfg.memory_regions.is_empty(), "should find /memory");
        assert!(cfg.serial.is_some(), "should find PL011 UART");
        assert!(cfg.interrupt_controller.is_some(), "should find GIC");
    }

    #[test]
    fn fdt_unknown_compatible_ignored() {
        let dtb = include_bytes!("../tests/fixtures/qemu-virt.dtb");
        let cfg = parse_fdt_for_test(dtb);
        // Unknown compatible strings are silently ignored.
        // The config should have populated fields for known devices only.
        assert!(cfg.serial.as_ref().unwrap().compatible == "arm,pl011");
    }

    #[test]
    fn fdt_chosen_bootargs() {
        // This test uses the QEMU DTB which typically has no bootargs.
        let dtb = include_bytes!("../tests/fixtures/qemu-virt.dtb");
        let cfg = parse_fdt_for_test(dtb);
        // bootargs may or may not be present depending on QEMU config.
        // Just verify it doesn't panic.
        let _ = cfg.chosen.bootargs;
    }
```

Generate the fixture DTB and commit it (if QEMU is available on the dev machine). If not, the subagent should skip the QEMU dump step and use a TODO comment noting the fixture needs to be generated.

- [ ] **Step 5: Verify boot crate compiles**

Run: `cd crates/harmony-boot-aarch64 && cargo check --target aarch64-unknown-uefi`
Expected: Compiles (may need nightly for UEFI target — if so, just verify syntax with `cargo check` on host target)

If the UEFI target isn't available, verify syntax:
Run: `cd crates/harmony-boot-aarch64 && cargo check 2>&1 | head -5`
(May fail on `uefi` crate import — that's OK, we just want to verify fdt_parse.rs compiles)

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-boot-aarch64/Cargo.toml crates/harmony-boot-aarch64/src/fdt_parse.rs crates/harmony-boot-aarch64/src/main.rs crates/harmony-microkernel/Cargo.toml
git commit -m "feat(boot-aarch64): add FDT parsing module with HardwareConfig population"
```

---

### Task 8: Buddy Allocator Verification and Full Test Suite

**Files:**
- Modify: `crates/harmony-microkernel/src/vm/buddy.rs` (doc comment only)

- [ ] **Step 1: Run existing buddy allocator tests under page-16k**

Run: `cargo test -p harmony-microkernel --features page-16k -- buddy`
Expected: PASS — buddy allocator already uses `PAGE_SIZE` and `PAGE_SHIFT` throughout

- [ ] **Step 2: Add 16K-specific verification test**

In the buddy allocator test module (`crates/harmony-microkernel/src/vm/buddy.rs`), add:

```rust
    #[test]
    fn frame_size_matches_page_size() {
        use super::super::{PAGE_SHIFT, PAGE_SIZE};
        // Order 0 allocation = 1 frame = PAGE_SIZE bytes.
        let base = PhysAddr(PAGE_SIZE * 16); // arbitrary aligned base
        let alloc = BuddyAllocator::new(base, 16).unwrap();
        // Frame count should be 16 regardless of page size.
        assert_eq!(alloc.frame_count(), 16);
    }
```

- [ ] **Step 3: Update doc comment**

In `crates/harmony-microkernel/src/vm/buddy.rs`, line 5, replace:

```rust
//! Supports allocation at power-of-two orders (order 0 = 1 frame = 4 KiB,
//! order 10 = 1024 frames = 4 MiB), splitting larger blocks down to serve
```

with:

```rust
//! Supports allocation at power-of-two orders (order 0 = 1 frame = PAGE_SIZE,
//! order 10 = 1024 frames), splitting larger blocks down to serve
```

- [ ] **Step 4: Run full test suite with both features**

Run: `cargo test -p harmony-microkernel`
Expected: ALL PASS

Run: `cargo test -p harmony-microkernel --features page-16k`
Expected: ALL PASS

- [ ] **Step 5: Run full workspace test**

Run: `cargo test --workspace`
Expected: ALL PASS (default 4K)

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-microkernel/src/vm/buddy.rs
git commit -m "test(microkernel): verify buddy allocator under 16K page granule"
```

---

### Task 9: Final Integration — Feature Propagation and CI

**Files:**
- Modify: `crates/harmony-boot-aarch64/Cargo.toml` (add `page-16k` feature)
- No CI config file exists yet — just document the command

- [ ] **Step 1: Add `page-16k` feature to boot crate**

In `crates/harmony-boot-aarch64/Cargo.toml`, update features:

```toml
[features]
default = ["qemu-virt"]
qemu-virt = []
rpi5 = []
page-16k = ["harmony-microkernel/page-16k"]
```

- [ ] **Step 2: Verify workspace builds cleanly with both feature sets**

Run: `cargo build --workspace`
Expected: SUCCESS

Run: `cargo build --workspace --features harmony-microkernel/page-16k`
Expected: SUCCESS

- [ ] **Step 3: Run full test suite with page-16k**

Run: `cargo test --workspace --features harmony-microkernel/page-16k`
Expected: ALL PASS

- [ ] **Step 4: Document CI test command**

The 16K test suite should be a separate CI job. Document this in the workspace justfile or a comment in the spec. The command is:

```bash
cargo test --workspace --features harmony-microkernel/page-16k
```

For QEMU integration testing (future):
```bash
qemu-system-aarch64 -machine virt -cpu max,pagesize=16k -kernel harmony-unikernel.bin
```

- [ ] **Step 5: Final commit**

```bash
git add crates/harmony-boot-aarch64/Cargo.toml
git commit -m "feat: complete page-16k feature propagation across crate graph"
```
