# EL2 Micro-VM Hypervisor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a thin EL2 hypervisor shim that can boot a bare-metal guest stub inside an isolated Stage-2 address space on aarch64.

**Architecture:** Sans-I/O hypervisor state machine (`TrapEvent` → `HypervisorAction`) in a new `harmony-hypervisor` workspace crate. Platform shim (assembly vectors, register access) stays in `harmony-boot-aarch64`. Microkernel drops to EL1 unchanged.

**Tech Stack:** Rust (no_std + alloc), aarch64 inline assembly (platform shim only), bitflags, existing `BuddyAllocator`/`VmError`/`PhysAddr` from `harmony-microkernel`

**Spec:** `docs/superpowers/specs/2026-03-26-el2-hypervisor-design.md`

**Scope:** This plan covers the pure Rust `harmony-hypervisor` workspace crate only — the sans-I/O state machine, types, and unit tests. The following are **deferred to a separate plan**:
- `harmony-boot-aarch64` changes (VBAR_EL2 assembly vectors, HCR_EL2 configuration, EL2→EL1 drop)
- QEMU integration tests (require custom `#![no_main]` harness targeting `aarch64-unknown-none`)
- RPi5 smoke tests

These depend on the sans-I/O crate being complete and will be planned as a follow-up.

---

## File Structure

### New crate: `crates/harmony-hypervisor/`

| File | Responsibility |
|------|---------------|
| `Cargo.toml` | Workspace member, depends on harmony-microkernel (for PhysAddr, VmError) |
| `src/lib.rs` | Crate root, re-exports public types |
| `src/vmid.rs` | `VmId` newtype + `VmIdAllocator` (8-bit, 0 reserved for host) |
| `src/trap.rs` | `TrapEvent`, `AccessType`, `HypervisorAction`, `HypervisorError`, HVC constants |
| `src/stage2.rs` | `Stage2PageTable`, `Stage2Flags`, `Stage2MemAttr` — Stage-2 page table builder |
| `src/vcpu.rs` | `VCpuContext`, `Vm`, `VmState` — per-VM state |
| `src/hypervisor.rs` | `Hypervisor` state machine — the sans-I/O core |
| `src/platform/mod.rs` | `PlatformConstants` trait, virtual UART IPA constant |
| `src/platform/qemu_virt.rs` | QEMU virt machine constants |
| `src/platform/rpi5.rs` | RPi5 BCM2712 constants |

### Modified: `Cargo.toml` (workspace root)

Add `harmony-hypervisor` to `[workspace] members` and `[workspace.dependencies]`.

---

## Task 1: Scaffold `harmony-hypervisor` crate with VmId and VMID allocator

**Files:**
- Create: `crates/harmony-hypervisor/Cargo.toml`
- Create: `crates/harmony-hypervisor/src/lib.rs`
- Create: `crates/harmony-hypervisor/src/vmid.rs`
- Modify: `Cargo.toml` (workspace root — add member + dependency)

**Context:**
- Follow `harmony-microkernel/Cargo.toml` as the template for workspace member setup
- `VmId(u8)` with 0 reserved for host, allocator tracks a 256-bit bitmap
- The workspace root `Cargo.toml` is at `/Users/zeblith/work/zeblithic/harmony-os/Cargo.toml`

- [ ] **Step 1: Write the failing test for VmId and VmIdAllocator**

```rust
// crates/harmony-hypervisor/src/vmid.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmid_zero_reserved_for_host() {
        let mut alloc = VmIdAllocator::new();
        // First allocation should be VmId(1), not 0
        let id = alloc.alloc().unwrap();
        assert_eq!(id, VmId(1));
    }

    #[test]
    fn vmid_alloc_sequential() {
        let mut alloc = VmIdAllocator::new();
        let a = alloc.alloc().unwrap();
        let b = alloc.alloc().unwrap();
        assert_eq!(a, VmId(1));
        assert_eq!(b, VmId(2));
    }

    #[test]
    fn vmid_free_and_reuse() {
        let mut alloc = VmIdAllocator::new();
        let id = alloc.alloc().unwrap();
        alloc.free(id);
        let reused = alloc.alloc().unwrap();
        assert_eq!(reused, id);
    }

    #[test]
    fn vmid_exhaustion() {
        let mut alloc = VmIdAllocator::new();
        // Allocate all 255 slots (1..=255)
        for _ in 0..255 {
            alloc.alloc().unwrap();
        }
        assert!(alloc.alloc().is_none());
    }

    #[test]
    fn vmid_free_zero_is_noop() {
        let mut alloc = VmIdAllocator::new();
        // Freeing VmId(0) should not make slot 0 allocatable
        alloc.free(VmId(0));
        let id = alloc.alloc().unwrap();
        assert_eq!(id, VmId(1)); // Still starts at 1
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-hypervisor`
Expected: Compilation error — crate doesn't exist yet

- [ ] **Step 3: Create crate scaffold and implement VmId + VmIdAllocator**

`crates/harmony-hypervisor/Cargo.toml`:
```toml
[package]
name = "harmony-hypervisor"
description = "EL2 micro-VM hypervisor — sans-I/O state machine for aarch64 virtualization"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[features]
default = []

[dependencies]
harmony-microkernel = { workspace = true, default-features = false }
```

`crates/harmony-hypervisor/src/lib.rs`:
```rust
// SPDX-License-Identifier: GPL-2.0-or-later
#![cfg_attr(not(test), no_std)]
extern crate alloc;

pub mod vmid;
```

`crates/harmony-hypervisor/src/vmid.rs`:
```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! VMID allocator — 8-bit namespace, max 256 VMs.
//!
//! VmId(0) is reserved for the host (no Stage-2 restriction).
//! Allocation starts at 1 and wraps around, using a 256-bit bitmap.

/// 8-bit VM identifier. VmId(0) is the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VmId(pub u8);

/// Bitmap-based VMID allocator. Slot 0 is permanently reserved.
pub struct VmIdAllocator {
    /// 256-bit bitmap: bit N set = slot N is in use.
    bitmap: [u64; 4],
}

impl VmIdAllocator {
    /// Create a new allocator with slot 0 pre-reserved.
    pub fn new() -> Self {
        let mut bitmap = [0u64; 4];
        bitmap[0] = 1; // Reserve bit 0 (host)
        Self { bitmap }
    }

    /// Allocate the next free VMID, or `None` if all 255 slots are in use.
    pub fn alloc(&mut self) -> Option<VmId> {
        for (chunk_idx, chunk) in self.bitmap.iter_mut().enumerate() {
            if *chunk != u64::MAX {
                let bit = (!*chunk).trailing_zeros() as u8;
                let id = (chunk_idx as u8) * 64 + bit;
                *chunk |= 1u64 << bit;
                return Some(VmId(id));
            }
        }
        None
    }

    /// Free a previously allocated VMID. Freeing VmId(0) is a no-op.
    pub fn free(&mut self, id: VmId) {
        if id.0 == 0 {
            return;
        }
        let chunk_idx = (id.0 / 64) as usize;
        let bit = id.0 % 64;
        self.bitmap[chunk_idx] &= !(1u64 << bit);
    }
}
```

Add to workspace root `Cargo.toml`:
- In `[workspace] members`: add `"crates/harmony-hypervisor"`
- In `[workspace.dependencies]`: add `harmony-hypervisor = { path = "crates/harmony-hypervisor", default-features = false }`

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-hypervisor`
Expected: All 5 tests pass

- [ ] **Step 5: Run workspace-wide checks**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: Clean clippy, all tests pass

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-hypervisor/ Cargo.toml Cargo.lock
git commit -m "feat(hypervisor): scaffold harmony-hypervisor crate with VmId allocator"
```

---

## Task 2: Trap types and HVC constants

**Files:**
- Create: `crates/harmony-hypervisor/src/trap.rs`
- Modify: `crates/harmony-hypervisor/src/lib.rs` (add `pub mod trap`)

**Context:**
- The spec defines `TrapEvent`, `AccessType`, `HypervisorAction`, `HypervisorError`, and HVC function IDs
- `HypervisorAction` references types from other modules (`VmId`, `PhysAddr`, `Stage2Flags`)
- For this task, `Stage2Flags` doesn't exist yet — define it inline here or use a forward reference
- `PhysAddr` comes from `harmony_microkernel::vm::PhysAddr`
- `VmError` comes from `harmony_microkernel::vm::VmError`

- [ ] **Step 1: Write the failing test for trap types**

```rust
// In crates/harmony-hypervisor/src/trap.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmid::VmId;

    #[test]
    fn hvc_constants_have_hv_prefix() {
        // "HV" in ASCII = 0x4856
        assert_eq!(HVC_VM_CREATE >> 16, 0x4856);
        assert_eq!(HVC_VM_DESTROY >> 16, 0x4856);
        assert_eq!(HVC_VM_START >> 16, 0x4856);
        assert_eq!(HVC_VM_MAP >> 16, 0x4856);
        assert_eq!(HVC_GUEST_EXIT >> 16, 0x4856);
    }

    #[test]
    fn hvc_constants_are_unique() {
        let ids = [HVC_VM_CREATE, HVC_VM_DESTROY, HVC_VM_START, HVC_VM_MAP, HVC_GUEST_EXIT];
        for (i, a) in ids.iter().enumerate() {
            for b in &ids[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn trap_event_variants_constructible() {
        let _hvc = TrapEvent::HvcCall { x0: 0, x1: 0, x2: 0, x3: 0 };
        let _da = TrapEvent::DataAbort {
            ipa: 0x0900_0000,
            access: AccessType::Write { value: b'H' as u64 },
            width: 1,
        };
        let _ia = TrapEvent::InstructionAbort { ipa: 0x4000_0000 };
        let _wfi = TrapEvent::WfiWfe;
        let _smc = TrapEvent::SmcForward { x0: 0, x1: 0, x2: 0, x3: 0 };
    }

    #[test]
    fn hypervisor_error_variants_constructible() {
        let _a = HypervisorError::VmLimitReached;
        let _b = HypervisorError::InvalidVmId(VmId(42));
        let _c = HypervisorError::InvalidHvc(0xDEAD);
        let _d = HypervisorError::VmAlreadyRunning(VmId(1));
        let _e = HypervisorError::OutOfMemory;
    }

    #[test]
    fn vm_map_pack_unpack_round_trips() {
        let vmid = 5u8;
        let flags_bits = 0b00_111u8; // RWX, MemAttr=0
        let page_count = 8u16;
        let packed = pack_vm_map_x1(vmid, flags_bits, page_count);
        let (v, f, p) = unpack_vm_map_x1(packed);
        assert_eq!(v, vmid);
        assert_eq!(f, flags_bits);
        assert_eq!(p, page_count);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-hypervisor`
Expected: Compilation error — `trap` module doesn't exist

- [ ] **Step 3: Implement trap types**

```rust
// crates/harmony-hypervisor/src/trap.rs
// SPDX-License-Identifier: GPL-2.0-or-later
//! Trap event/action types, HVC constants, and error enum.

use crate::vmid::VmId;
use harmony_microkernel::vm::{PhysAddr, VmError};

// ── HVC Function IDs ─────────────────────────────────────────────────

/// "HV" prefix (0x4856) places these in the vendor-specific HVC range.
pub const HVC_VM_CREATE: u64 = 0x4856_0001;
pub const HVC_VM_DESTROY: u64 = 0x4856_0002;
pub const HVC_VM_START: u64 = 0x4856_0003;
pub const HVC_VM_MAP: u64 = 0x4856_0010;
pub const HVC_GUEST_EXIT: u64 = 0x4856_0099;

// ── VM_MAP x1 packing ───────────────────────────────────────────────

/// Pack VMID, flags, and page_count into a single u64 for HVC_VM_MAP x1.
/// Layout: bits [7:0]=VMID, [15:8]=flags, [31:16]=page_count.
pub fn pack_vm_map_x1(vmid: u8, flags: u8, page_count: u16) -> u64 {
    (vmid as u64) | ((flags as u64) << 8) | ((page_count as u64) << 16)
}

/// Unpack HVC_VM_MAP x1 into (vmid, flags, page_count).
pub fn unpack_vm_map_x1(x1: u64) -> (u8, u8, u16) {
    let vmid = (x1 & 0xFF) as u8;
    let flags = ((x1 >> 8) & 0xFF) as u8;
    let page_count = ((x1 >> 16) & 0xFFFF) as u16;
    (vmid, flags, page_count)
}

// ── Events ───────────────────────────────────────────────────────────

/// Events fed into the hypervisor by the platform shim after parsing ESR_EL2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrapEvent {
    HvcCall { x0: u64, x1: u64, x2: u64, x3: u64 },
    DataAbort { ipa: u64, access: AccessType, width: u8 },
    InstructionAbort { ipa: u64 },
    WfiWfe,
    SmcForward { x0: u64, x1: u64, x2: u64, x3: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessType {
    Read,
    Write { value: u64 },
}

// ── Actions ──────────────────────────────────────────────────────────

/// Actions the hypervisor returns for the platform shim to execute.
///
/// Note: Stage-2 page table manipulation happens inside `handle()` via
/// pure memory writes through `phys_to_virt` (same pattern as the existing
/// Stage-1 `Aarch64PageTable`). This is not I/O — it's data structure
/// manipulation. The platform shim must perform TLB invalidation
/// (TLBI IPAS2E1IS + TLBI VMALLE1IS + DSB ISH + ISB) after any
/// `HvcResult` returned from `HVC_VM_MAP`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HypervisorAction {
    ResumeGuest,
    CreateVm { vmid: VmId, stage2_root: PhysAddr },
    DestroyVm { vmid: VmId },
    EmitChar { ch: u8 },
    ForwardSmc { x0: u64, x1: u64, x2: u64, x3: u64 },
    EnterGuest { vmid: VmId },
    HvcResult { x0: u64 },
}

// ── Stage-2 flags (used by actions, defined here to avoid circular deps) ─

/// Stage-2 permission and memory attribute flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stage2Flags {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub mem_attr: Stage2MemAttr,
}

/// Stage-2 memory attribute (encoded directly in descriptor, no MAIR).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage2MemAttr {
    NormalWriteBack,
    NormalNonCacheable,
    Device,
}

impl Stage2Flags {
    /// RWX normal write-back — the common case for guest RAM.
    pub const GUEST_RAM: Self = Self {
        readable: true,
        writable: true,
        executable: true,
        mem_attr: Stage2MemAttr::NormalWriteBack,
    };
}

// ── Errors ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HypervisorError {
    VmLimitReached,
    InvalidVmId(VmId),
    InvalidHvc(u64),
    Stage2MapFailed(VmError),
    VmAlreadyRunning(VmId),
    OutOfMemory,
}
```

Update `src/lib.rs` to add `pub mod trap;`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-hypervisor`
Expected: All tests pass (vmid + trap)

- [ ] **Step 5: Run workspace-wide checks**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: Clean

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-hypervisor/src/trap.rs crates/harmony-hypervisor/src/lib.rs
git commit -m "feat(hypervisor): add TrapEvent, HypervisorAction, HVC constants"
```

---

## Task 3: Stage-2 page table builder

**Files:**
- Create: `crates/harmony-hypervisor/src/stage2.rs`
- Modify: `crates/harmony-hypervisor/src/lib.rs` (add `pub mod stage2`)

**Context:**
- Follow the pattern of `harmony-microkernel/src/vm/aarch64.rs` closely — same 4-level, 4KiB granule, 512-entry tables
- Key differences from Stage-1: S2AP[1:0] instead of AP[2:1], XN[1:0] instead of UXN/PXN, MemAttr[3:0] directly in descriptor instead of MAIR index
- `phys_to_virt: fn(PhysAddr) -> *mut u8` matches existing convention
- Frame allocation uses `&mut dyn FnMut() -> Option<PhysAddr>` callback (same pattern as Stage-1's `map()`)
- Reference: `crates/harmony-microkernel/src/vm/aarch64.rs` lines 88-254 for the Stage-1 implementation

- [ ] **Step 1: Write the failing tests for Stage-2 page table**

```rust
// In crates/harmony-hypervisor/src/stage2.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::trap::{Stage2Flags, Stage2MemAttr};
    use harmony_microkernel::vm::PhysAddr;
    use alloc::vec::Vec;

    const PAGE_SIZE: u64 = 4096;

    /// Test arena: a heap-allocated chunk of memory where "physical" frames live.
    /// phys_to_virt is identity (addr → pointer to our arena).
    struct TestArena {
        memory: Vec<u8>,
        base: usize,
        next_free: usize,
    }

    impl TestArena {
        fn new(num_pages: usize) -> Self {
            let memory = vec![0u8; num_pages * PAGE_SIZE as usize];
            let base = memory.as_ptr() as usize;
            // Align to page boundary
            let aligned_base = (base + PAGE_SIZE as usize - 1) & !(PAGE_SIZE as usize - 1);
            Self { memory, base: aligned_base, next_free: aligned_base }
        }

        fn alloc_frame(&mut self) -> Option<PhysAddr> {
            let end = self.memory.as_ptr() as usize + self.memory.len();
            if self.next_free + PAGE_SIZE as usize > end {
                return None;
            }
            let addr = self.next_free;
            self.next_free += PAGE_SIZE as usize;
            // Zero the frame
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, PAGE_SIZE as usize); }
            Some(PhysAddr(addr as u64))
        }

        fn phys_to_virt(pa: PhysAddr) -> *mut u8 {
            pa.0 as *mut u8
        }
    }

    #[test]
    fn map_and_walk_single_page() {
        let mut arena = TestArena::new(64);
        let root = arena.alloc_frame().unwrap();
        let mut pt = Stage2PageTable::new(root, VmId(1), TestArena::phys_to_virt);
        let ipa = 0x4000_0000u64;
        let pa = PhysAddr(0x8000_0000);
        let flags = Stage2Flags::GUEST_RAM;
        pt.map(ipa, pa, flags, &mut || arena.alloc_frame()).unwrap();
        let result = pt.walk(ipa);
        assert_eq!(result, Some((pa, flags)));
    }

    #[test]
    fn walk_unmapped_returns_none() {
        let mut arena = TestArena::new(16);
        let root = arena.alloc_frame().unwrap();
        let pt = Stage2PageTable::new(root, VmId(1), TestArena::phys_to_virt);
        assert_eq!(pt.walk(0x4000_0000), None);
    }

    #[test]
    fn map_multiple_pages() {
        let mut arena = TestArena::new(64);
        let root = arena.alloc_frame().unwrap();
        let mut pt = Stage2PageTable::new(root, VmId(1), TestArena::phys_to_virt);
        for i in 0..4u64 {
            let ipa = 0x4000_0000 + i * PAGE_SIZE;
            let pa = PhysAddr(0x8000_0000 + i * PAGE_SIZE);
            pt.map(ipa, pa, Stage2Flags::GUEST_RAM, &mut || arena.alloc_frame()).unwrap();
        }
        for i in 0..4u64 {
            let ipa = 0x4000_0000 + i * PAGE_SIZE;
            let pa = PhysAddr(0x8000_0000 + i * PAGE_SIZE);
            assert_eq!(pt.walk(ipa), Some((pa, Stage2Flags::GUEST_RAM)));
        }
    }

    #[test]
    fn unmap_returns_pa() {
        let mut arena = TestArena::new(64);
        let root = arena.alloc_frame().unwrap();
        let mut pt = Stage2PageTable::new(root, VmId(1), TestArena::phys_to_virt);
        let pa = PhysAddr(0x8000_0000);
        pt.map(0x4000_0000, pa, Stage2Flags::GUEST_RAM, &mut || arena.alloc_frame()).unwrap();
        let unmapped = pt.unmap(0x4000_0000).unwrap();
        assert_eq!(unmapped, pa);
        assert_eq!(pt.walk(0x4000_0000), None);
    }

    #[test]
    fn unmap_unmapped_returns_error() {
        let mut arena = TestArena::new(16);
        let root = arena.alloc_frame().unwrap();
        let mut pt = Stage2PageTable::new(root, VmId(1), TestArena::phys_to_virt);
        assert!(pt.unmap(0x4000_0000).is_err());
    }

    #[test]
    fn unaligned_ipa_rejected() {
        let mut arena = TestArena::new(64);
        let root = arena.alloc_frame().unwrap();
        let mut pt = Stage2PageTable::new(root, VmId(1), TestArena::phys_to_virt);
        let result = pt.map(0x4000_0001, PhysAddr(0x8000_0000), Stage2Flags::GUEST_RAM, &mut || arena.alloc_frame());
        assert!(result.is_err());
    }

    #[test]
    fn descriptor_bits_correct_for_device_memory() {
        // Device memory should encode MemAttr=0b0000 in descriptor bits [5:2]
        let flags = Stage2Flags {
            readable: true,
            writable: false,
            executable: false,
            mem_attr: Stage2MemAttr::Device,
        };
        let desc = flags_to_desc(flags);
        // S2AP[7:6] = 0b01 (read-only)
        assert_eq!(desc & S2AP_MASK, S2AP_RO);
        // XN[54:53] = 0b11 (no execute at either EL)
        assert_ne!(desc & XN_MASK, 0);
        // MemAttr[5:2] = 0b0000 (device)
        assert_eq!(desc & MEMATTR_MASK, MEMATTR_DEVICE);
    }

    #[test]
    fn root_paddr_returns_root() {
        let mut arena = TestArena::new(16);
        let root = arena.alloc_frame().unwrap();
        let pt = Stage2PageTable::new(root, VmId(1), TestArena::phys_to_virt);
        assert_eq!(pt.root_paddr(), root);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-hypervisor`
Expected: Compilation error — `stage2` module doesn't exist

- [ ] **Step 3: Implement Stage-2 page table**

The implementation follows `aarch64.rs` structure with Stage-2 descriptor bits:

```rust
// crates/harmony-hypervisor/src/stage2.rs
// SPDX-License-Identifier: GPL-2.0-or-later
//! Stage-2 page table builder for EL2 hypervisor.
//!
//! Maps IPA (Intermediate Physical Address) → PA using 4-level, 4KiB granule
//! tables stored in VTTBR_EL2. Follows the same pattern as the Stage-1
//! implementation in `harmony_microkernel::vm::aarch64`, but with Stage-2
//! specific descriptor bits (S2AP, XN, direct MemAttr).

use crate::trap::{Stage2Flags, Stage2MemAttr};
use crate::vmid::VmId;
use harmony_microkernel::vm::{PhysAddr, VmError, PAGE_SIZE};

// ── Stage-2 descriptor bit constants ────────────────────────────────

/// Valid descriptor (bits [1:0] = 0b11 for table/page).
const DESC_VALID: u64 = 0b11;
const DESC_INVALID: u64 = 0b00;

/// Access Flag — must be set.
const AF: u64 = 1 << 10;
/// Inner Shareable.
const SH_INNER: u64 = 0b11 << 8;

/// S2AP[7:6]: Stage-2 access permissions.
const S2AP_NONE: u64 = 0b00 << 6;
const S2AP_RO: u64 = 0b01 << 6;
const S2AP_WO: u64 = 0b10 << 6;
const S2AP_RW: u64 = 0b11 << 6;
pub(crate) const S2AP_MASK: u64 = 0b11 << 6;

/// XN[54:53]: Execute-Never for EL1 and EL0.
const XN_NONE: u64 = 0;                     // Execute allowed
const XN_ALL: u64 = (0b11u64) << 53;        // No execute
pub(crate) const XN_MASK: u64 = 0b11u64 << 53;

/// MemAttr[5:2]: Memory attributes encoded directly in descriptor.
pub(crate) const MEMATTR_DEVICE: u64 = 0b0000 << 2;       // Device-nGnRnE
const MEMATTR_NORMAL_NC: u64 = 0b0101 << 2;  // Normal Non-Cacheable
const MEMATTR_NORMAL_WB: u64 = 0b1111 << 2;  // Normal Write-Back
pub(crate) const MEMATTR_MASK: u64 = 0b1111 << 2;

/// Address mask for extracting output address (bits [47:12]).
const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

// ── Descriptor helpers ──────────────────────────────────────────────

/// Convert Stage2Flags to a Stage-2 leaf descriptor.
pub(crate) fn flags_to_desc(flags: Stage2Flags) -> u64 {
    let mut desc: u64 = DESC_VALID | AF | SH_INNER;

    // S2AP
    desc |= match (flags.readable, flags.writable) {
        (true, true) => S2AP_RW,
        (true, false) => S2AP_RO,
        (false, true) => S2AP_WO,
        (false, false) => S2AP_NONE,
    };

    // XN
    if !flags.executable {
        desc |= XN_ALL;
    }

    // MemAttr
    desc |= match flags.mem_attr {
        Stage2MemAttr::NormalWriteBack => MEMATTR_NORMAL_WB,
        Stage2MemAttr::NormalNonCacheable => MEMATTR_NORMAL_NC,
        Stage2MemAttr::Device => MEMATTR_DEVICE,
    };

    desc
}

/// Convert a Stage-2 leaf descriptor back to Stage2Flags.
fn desc_to_flags(desc: u64) -> Stage2Flags {
    let s2ap = desc & S2AP_MASK;
    let readable = s2ap == S2AP_RO || s2ap == S2AP_RW;
    let writable = s2ap == S2AP_WO || s2ap == S2AP_RW;
    let executable = desc & XN_MASK == XN_NONE;
    let mem_attr = match desc & MEMATTR_MASK {
        MEMATTR_NORMAL_WB => Stage2MemAttr::NormalWriteBack,
        MEMATTR_NORMAL_NC => Stage2MemAttr::NormalNonCacheable,
        _ => Stage2MemAttr::Device,
    };
    Stage2Flags { readable, writable, executable, mem_attr }
}

// ── Stage2PageTable ─────────────────────────────────────────────────

/// Stage-2 page table for a single VM.
pub struct Stage2PageTable {
    root: PhysAddr,
    vmid: VmId,
    phys_to_virt: fn(PhysAddr) -> *mut u8,
}

impl Stage2PageTable {
    /// Create a new Stage-2 page table.
    ///
    /// `root` must point to a zeroed, 4KiB-aligned frame.
    pub fn new(root: PhysAddr, vmid: VmId, phys_to_virt: fn(PhysAddr) -> *mut u8) -> Self {
        Self { root, vmid, phys_to_virt }
    }

    pub fn root_paddr(&self) -> PhysAddr { self.root }
    pub fn vmid(&self) -> VmId { self.vmid }

    /// Map a single 4KiB page: IPA → PA with given flags.
    pub fn map(
        &mut self,
        ipa: u64,
        pa: PhysAddr,
        flags: Stage2Flags,
        frame_alloc: &mut dyn FnMut() -> Option<PhysAddr>,
    ) -> Result<(), VmError> {
        if ipa & (PAGE_SIZE - 1) != 0 {
            return Err(VmError::Unaligned(ipa));
        }
        if !pa.is_page_aligned() {
            return Err(VmError::Unaligned(pa.as_u64()));
        }

        let mut table_paddr = self.root;
        // Walk levels 3 → 1 (L0 → L2), creating intermediate tables as needed.
        for level in (1..=3).rev() {
            let table = self.table_mut(table_paddr);
            let idx = Self::index(ipa, level);
            let entry = table[idx];

            if entry & 0b11 != DESC_INVALID {
                table_paddr = PhysAddr(entry & ADDR_MASK);
            } else {
                let new_frame = frame_alloc().ok_or(VmError::OutOfMemory)?;
                let new_ptr = (self.phys_to_virt)(new_frame);
                unsafe { core::ptr::write_bytes(new_ptr, 0, PAGE_SIZE as usize); }
                table[idx] = (new_frame.as_u64() & ADDR_MASK) | DESC_VALID;
                table_paddr = new_frame;
            }
        }

        // Write leaf entry at L3.
        let table = self.table_mut(table_paddr);
        let idx = Self::index(ipa, 0);
        table[idx] = (pa.as_u64() & ADDR_MASK) | flags_to_desc(flags);
        Ok(())
    }

    /// Unmap a single 4KiB page, returning the PA that was mapped.
    pub fn unmap(&mut self, ipa: u64) -> Result<PhysAddr, VmError> {
        if ipa & (PAGE_SIZE - 1) != 0 {
            return Err(VmError::Unaligned(ipa));
        }

        let mut table_paddr = self.root;
        for level in (1..=3).rev() {
            let table = self.table_mut(table_paddr);
            let idx = Self::index(ipa, level);
            let entry = table[idx];
            if entry & 0b11 == DESC_INVALID {
                return Err(VmError::NotMapped(harmony_microkernel::vm::VirtAddr(ipa)));
            }
            table_paddr = PhysAddr(entry & ADDR_MASK);
        }

        let table = self.table_mut(table_paddr);
        let idx = Self::index(ipa, 0);
        let entry = table[idx];
        if entry & 0b11 == DESC_INVALID {
            return Err(VmError::NotMapped(harmony_microkernel::vm::VirtAddr(ipa)));
        }
        let pa = PhysAddr(entry & ADDR_MASK);
        table[idx] = DESC_INVALID;
        Ok(pa)
    }

    /// Walk the table and return the mapped PA + flags, or None if unmapped.
    pub fn walk(&self, ipa: u64) -> Option<(PhysAddr, Stage2Flags)> {
        let mut table_paddr = self.root;
        for level in (1..=3).rev() {
            let table = self.table_ref(table_paddr);
            let idx = Self::index(ipa, level);
            let entry = table[idx];
            if entry & 0b11 == DESC_INVALID {
                return None;
            }
            table_paddr = PhysAddr(entry & ADDR_MASK);
        }
        let table = self.table_ref(table_paddr);
        let idx = Self::index(ipa, 0);
        let entry = table[idx];
        if entry & 0b11 == DESC_INVALID {
            return None;
        }
        Some((PhysAddr(entry & ADDR_MASK), desc_to_flags(entry)))
    }

    fn table_mut(&self, table_paddr: PhysAddr) -> &mut [u64; 512] {
        let ptr = (self.phys_to_virt)(table_paddr);
        unsafe { &mut *(ptr as *mut [u64; 512]) }
    }

    fn table_ref(&self, table_paddr: PhysAddr) -> &[u64; 512] {
        let ptr = (self.phys_to_virt)(table_paddr);
        unsafe { &*(ptr as *const [u64; 512]) }
    }

    fn index(ipa: u64, level: usize) -> usize {
        ((ipa >> (12 + level * 9)) & 0x1FF) as usize
    }
}
```

Update `src/lib.rs` to add `pub mod stage2;`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-hypervisor`
Expected: All tests pass

- [ ] **Step 5: Run workspace-wide checks**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: Clean

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-hypervisor/src/stage2.rs crates/harmony-hypervisor/src/lib.rs
git commit -m "feat(hypervisor): add Stage-2 page table builder"
```

---

## Task 4: vCPU context and VM struct

**Files:**
- Create: `crates/harmony-hypervisor/src/vcpu.rs`
- Modify: `crates/harmony-hypervisor/src/lib.rs` (add `pub mod vcpu`)

**Context:**
- `VCpuContext` holds all saved registers (GPRs, SP_EL0/EL1, ELR/SPSR_EL2, EL1 system regs, timer)
- `Vm` bundles VCpuContext + Stage2PageTable + VmState
- The host is represented as a `VCpuContext` without a Stage-2 table (managed separately in `Hypervisor`)

- [ ] **Step 1: Write the failing test**

```rust
// In crates/harmony-hypervisor/src/vcpu.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcpu_context_default_is_zeroed() {
        let ctx = VCpuContext::default();
        assert_eq!(ctx.x, [0u64; 31]);
        assert_eq!(ctx.sp_el0, 0);
        assert_eq!(ctx.sp_el1, 0);
        assert_eq!(ctx.elr_el2, 0);
        assert_eq!(ctx.spsr_el2, 0);
        assert_eq!(ctx.sctlr_el1, 0);
    }

    #[test]
    fn vm_state_transitions() {
        assert_eq!(VmState::Created, VmState::Created);
        assert_ne!(VmState::Created, VmState::Running);
        assert_ne!(VmState::Running, VmState::Halted);
    }

    #[test]
    fn vcpu_context_set_entry_point() {
        let mut ctx = VCpuContext::default();
        ctx.elr_el2 = 0x4000_0000;
        // SPSR_EL2 = EL1h (0b0101), all exceptions masked (DAIF)
        ctx.spsr_el2 = 0x3C5;
        assert_eq!(ctx.elr_el2, 0x4000_0000);
        assert_eq!(ctx.spsr_el2, 0x3C5);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-hypervisor`
Expected: Compilation error — `vcpu` module doesn't exist

- [ ] **Step 3: Implement VCpuContext and Vm**

```rust
// crates/harmony-hypervisor/src/vcpu.rs
// SPDX-License-Identifier: GPL-2.0-or-later
//! vCPU context and VM state.

use crate::stage2::Stage2PageTable;
use crate::vmid::VmId;

/// Saved register state for a virtual CPU.
///
/// The asm shim saves/restores these on every EL2 trap and guest entry.
#[derive(Debug, Clone)]
pub struct VCpuContext {
    // General-purpose registers
    pub x: [u64; 31],
    pub sp_el0: u64,
    pub sp_el1: u64,

    // Trap state (saved by hardware on trap to EL2)
    pub elr_el2: u64,
    pub spsr_el2: u64,

    // EL1 system registers the guest owns
    pub sctlr_el1: u64,
    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
    pub tcr_el1: u64,
    pub mair_el1: u64,
    pub vbar_el1: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub contextidr_el1: u64,

    // Virtual timer
    pub cntv_ctl_el0: u64,
    pub cntv_cval_el0: u64,
}

impl Default for VCpuContext {
    fn default() -> Self {
        Self {
            x: [0; 31],
            sp_el0: 0,
            sp_el1: 0,
            elr_el2: 0,
            spsr_el2: 0,
            sctlr_el1: 0,
            ttbr0_el1: 0,
            ttbr1_el1: 0,
            tcr_el1: 0,
            mair_el1: 0,
            vbar_el1: 0,
            elr_el1: 0,
            spsr_el1: 0,
            contextidr_el1: 0,
            cntv_ctl_el0: 0,
            cntv_cval_el0: 0,
        }
    }
}

/// State of a virtual machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    Created,
    Running,
    Halted,
}

/// A virtual machine: vCPU context + Stage-2 address space.
pub struct Vm {
    pub id: VmId,
    pub vcpu: VCpuContext,
    pub stage2: Stage2PageTable,
    pub state: VmState,
}
```

Update `src/lib.rs` to add `pub mod vcpu;`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-hypervisor`
Expected: All tests pass

- [ ] **Step 5: Run workspace-wide checks**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: Clean

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-hypervisor/src/vcpu.rs crates/harmony-hypervisor/src/lib.rs
git commit -m "feat(hypervisor): add VCpuContext and Vm structs"
```

---

## Task 5: Platform constants

**Files:**
- Create: `crates/harmony-hypervisor/src/platform/mod.rs`
- Create: `crates/harmony-hypervisor/src/platform/qemu_virt.rs`
- Create: `crates/harmony-hypervisor/src/platform/rpi5.rs`
- Modify: `crates/harmony-hypervisor/src/lib.rs` (add `pub mod platform`)

**Context:**
- The virtual UART IPA (`0x0900_0000`) is a convention, same on both platforms
- Platform-specific constants: GIC base addresses (for future use), RAM layout
- Follow the pattern in `harmony-boot-aarch64/src/platform.rs` (feature-gated constants)

- [ ] **Step 1: Write the failing test**

```rust
// In crates/harmony-hypervisor/src/platform/mod.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_uart_ipa_is_consistent() {
        assert_eq!(VIRTUAL_UART_IPA, 0x0900_0000);
    }

    #[test]
    fn guest_ram_base_is_page_aligned() {
        assert_eq!(GUEST_RAM_BASE_IPA & 0xFFF, 0);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-hypervisor`
Expected: Compilation error — `platform` module doesn't exist

- [ ] **Step 3: Implement platform constants**

`crates/harmony-hypervisor/src/platform/mod.rs`:
```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! Platform constants for the hypervisor.
//!
//! The virtual UART IPA is a convention (not real hardware), so it's
//! platform-independent. Platform-specific constants are in submodules.

pub mod qemu_virt;
pub mod rpi5;

/// Virtual UART IPA — guest writes here trigger Stage-2 data abort.
/// Uses QEMU virt PL011 address by convention for easy debugging.
pub const VIRTUAL_UART_IPA: u64 = 0x0900_0000;

/// Default guest RAM base IPA.
pub const GUEST_RAM_BASE_IPA: u64 = 0x4000_0000;

/// HVC ping function ID for EL2→EL1 drop validation.
pub const HVC_PING: u64 = 0x4856_FFFF;
/// Expected HVC ping response.
pub const HVC_PONG: u64 = 0x4856_FFFE;
```

`crates/harmony-hypervisor/src/platform/qemu_virt.rs`:
```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! QEMU virt machine constants.

/// GICv3 distributor base (QEMU virt).
pub const GICD_BASE: u64 = 0x0800_0000;
/// GICv3 redistributor base (QEMU virt).
pub const GICR_BASE: u64 = 0x080A_0000;
```

`crates/harmony-hypervisor/src/platform/rpi5.rs`:
```rust
// SPDX-License-Identifier: GPL-2.0-or-later
//! RPi5 (BCM2712) constants.

/// GIC-600 distributor base (BCM2712).
pub const GICD_BASE: u64 = 0xFF84_1000;
/// GIC-600 redistributor base (BCM2712).
pub const GICR_BASE: u64 = 0xFF84_2000;
```

Update `src/lib.rs` to add `pub mod platform;`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-hypervisor`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-hypervisor/src/platform/ crates/harmony-hypervisor/src/lib.rs
git commit -m "feat(hypervisor): add platform constants (QEMU virt + RPi5)"
```

---

## Task 6: Hypervisor state machine — the sans-I/O core

**Files:**
- Create: `crates/harmony-hypervisor/src/hypervisor.rs`
- Modify: `crates/harmony-hypervisor/src/lib.rs` (add `pub mod hypervisor`)

**Context:**
- This is the main brain: accepts `TrapEvent`, returns `Result<HypervisorAction, HypervisorError>`
- Owns a `VmIdAllocator`, a `BTreeMap<VmId, Vm>`, and a host `VCpuContext`
- HVC dispatch: match on x0 to function ID, decode arguments, perform action
- DataAbort: check if IPA matches virtual UART → EmitChar, otherwise → DestroyVm
- WfiWfe: halt the guest, return to host
- SmcForward: forward to EL3 (PSCI)
- VM lifecycle: create → map → start → (trap loop) → destroy
- The `handle()` method takes `&mut self` and the event, returns single action
- Stage-2 page table frames come from a caller-provided allocator (stored as a closure or passed per-call)
- For simplicity, pass `frame_alloc` at VM creation time and store it isn't feasible (closures aren't storable in no_std without alloc::boxed::Box). Instead, `handle_with_alloc()` takes both the event and a frame allocator reference.

- [ ] **Step 1: Write the failing tests**

```rust
// In crates/harmony-hypervisor/src/hypervisor.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::trap::*;
    use crate::vmid::VmId;
    use crate::platform::VIRTUAL_UART_IPA;
    use harmony_microkernel::vm::PhysAddr;
    use alloc::vec::Vec;

    /// Simple bump allocator for tests.
    struct BumpAlloc {
        next: u64,
        limit: u64,
    }
    impl BumpAlloc {
        fn new(base: u64, size: u64) -> Self {
            Self { next: base, limit: base + size }
        }
        fn alloc(&mut self) -> Option<PhysAddr> {
            if self.next >= self.limit { return None; }
            let addr = self.next;
            self.next += 4096;
            Some(PhysAddr(addr))
        }
    }

    fn phys_to_virt_test(pa: PhysAddr) -> *mut u8 {
        pa.0 as *mut u8
    }

    fn make_hypervisor() -> Hypervisor {
        Hypervisor::new(phys_to_virt_test)
    }

    #[test]
    fn create_vm_returns_vmid() {
        let mut hyp = make_hypervisor();
        let mut alloc = BumpAlloc::new(0x10_0000, 0x10_0000);
        let action = hyp.handle(
            TrapEvent::HvcCall { x0: HVC_VM_CREATE, x1: 0, x2: 0, x3: 0 },
            &mut || alloc.alloc(),
        ).unwrap();
        match action {
            HypervisorAction::HvcResult { x0 } => assert_eq!(x0, 1), // VmId(1)
            other => panic!("expected HvcResult, got {:?}", other),
        }
    }

    #[test]
    fn create_vm_allocates_stage2_root() {
        let mut hyp = make_hypervisor();
        let mut alloc = BumpAlloc::new(0x10_0000, 0x10_0000);
        hyp.handle(
            TrapEvent::HvcCall { x0: HVC_VM_CREATE, x1: 0, x2: 0, x3: 0 },
            &mut || alloc.alloc(),
        ).unwrap();
        // Root frame was consumed from the allocator
        assert!(alloc.next > 0x10_0000);
    }

    #[test]
    fn destroy_nonexistent_vm_errors() {
        let mut hyp = make_hypervisor();
        let mut alloc = BumpAlloc::new(0x10_0000, 0x10_0000);
        let result = hyp.handle(
            TrapEvent::HvcCall { x0: HVC_VM_DESTROY, x1: 99, x2: 0, x3: 0 },
            &mut || alloc.alloc(),
        );
        assert!(matches!(result, Err(HypervisorError::InvalidVmId(VmId(99)))));
    }

    #[test]
    fn invalid_hvc_errors() {
        let mut hyp = make_hypervisor();
        let mut alloc = BumpAlloc::new(0x10_0000, 0x10_0000);
        let result = hyp.handle(
            TrapEvent::HvcCall { x0: 0xDEAD, x1: 0, x2: 0, x3: 0 },
            &mut || alloc.alloc(),
        );
        assert!(matches!(result, Err(HypervisorError::InvalidHvc(0xDEAD))));
    }

    #[test]
    fn vm_map_adds_stage2_entry() {
        let mut hyp = make_hypervisor();
        // Use a real heap-backed arena for the page table to walk
        let arena = vec![0u8; 64 * 4096];
        let arena_base = arena.as_ptr() as u64;
        let mut bump = arena_base;
        let mut frame_alloc = || {
            if bump >= arena_base + arena.len() as u64 { return None; }
            let addr = bump;
            bump += 4096;
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, 4096); }
            Some(PhysAddr(addr))
        };

        // Create VM
        hyp.handle(
            TrapEvent::HvcCall { x0: HVC_VM_CREATE, x1: 0, x2: 0, x3: 0 },
            &mut frame_alloc,
        ).unwrap();

        // Map a page: VMID=1, flags=RWX(0b111), 1 page
        let x1 = pack_vm_map_x1(1, 0b00_000_111, 1);
        let action = hyp.handle(
            TrapEvent::HvcCall { x0: HVC_VM_MAP, x1, x2: 0x4000_0000, x3: 0x8000_0000 },
            &mut frame_alloc,
        ).unwrap();
        assert!(matches!(action, HypervisorAction::HvcResult { x0: 0 }));
    }

    #[test]
    fn vm_start_returns_enter_guest() {
        let mut hyp = make_hypervisor();
        let arena = vec![0u8; 64 * 4096];
        let arena_base = arena.as_ptr() as u64;
        let mut bump = arena_base;
        let mut frame_alloc = || {
            if bump >= arena_base + arena.len() as u64 { return None; }
            let addr = bump;
            bump += 4096;
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, 4096); }
            Some(PhysAddr(addr))
        };

        // Create + start
        hyp.handle(
            TrapEvent::HvcCall { x0: HVC_VM_CREATE, x1: 0, x2: 0, x3: 0 },
            &mut frame_alloc,
        ).unwrap();
        let action = hyp.handle(
            TrapEvent::HvcCall { x0: HVC_VM_START, x1: 1, x2: 0x4000_0000, x3: 0 },
            &mut frame_alloc,
        ).unwrap();
        assert!(matches!(action, HypervisorAction::EnterGuest { vmid: VmId(1) }));
    }

    #[test]
    fn data_abort_at_uart_emits_char() {
        let mut hyp = make_hypervisor();
        let mut alloc = BumpAlloc::new(0x10_0000, 0x10_0000);
        let action = hyp.handle(
            TrapEvent::DataAbort {
                ipa: VIRTUAL_UART_IPA,
                access: AccessType::Write { value: b'H' as u64 },
                width: 1,
            },
            &mut || alloc.alloc(),
        ).unwrap();
        assert_eq!(action, HypervisorAction::EmitChar { ch: b'H' });
    }

    #[test]
    fn data_abort_at_unknown_ipa_destroys_vm() {
        let arena = vec![0u8; 64 * 4096];
        let arena_base = arena.as_ptr() as u64;
        let mut bump = arena_base;
        let mut frame_alloc = || {
            if bump >= arena_base + arena.len() as u64 { return None; }
            let addr = bump;
            bump += 4096;
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, 4096); }
            Some(PhysAddr(addr))
        };

        let mut hyp = Hypervisor::new(|pa| pa.0 as *mut u8);
        // Create and start a VM so active_vmid is set legitimately
        hyp.handle(
            TrapEvent::HvcCall { x0: HVC_VM_CREATE, x1: 0, x2: 0, x3: 0 },
            &mut frame_alloc,
        ).unwrap();
        hyp.handle(
            TrapEvent::HvcCall { x0: HVC_VM_START, x1: 1, x2: 0x4000_0000, x3: 0 },
            &mut frame_alloc,
        ).unwrap();

        let action = hyp.handle(
            TrapEvent::DataAbort {
                ipa: 0xDEAD_0000,
                access: AccessType::Read,
                width: 4,
            },
            &mut frame_alloc,
        ).unwrap();
        assert_eq!(action, HypervisorAction::DestroyVm { vmid: VmId(1) });
    }

    #[test]
    fn wfi_halts_guest() {
        let arena = vec![0u8; 64 * 4096];
        let arena_base = arena.as_ptr() as u64;
        let mut bump = arena_base;
        let mut frame_alloc = || {
            if bump >= arena_base + arena.len() as u64 { return None; }
            let addr = bump;
            bump += 4096;
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, 4096); }
            Some(PhysAddr(addr))
        };

        let mut hyp = Hypervisor::new(|pa| pa.0 as *mut u8);
        hyp.handle(
            TrapEvent::HvcCall { x0: HVC_VM_CREATE, x1: 0, x2: 0, x3: 0 },
            &mut frame_alloc,
        ).unwrap();
        hyp.handle(
            TrapEvent::HvcCall { x0: HVC_VM_START, x1: 1, x2: 0x4000_0000, x3: 0 },
            &mut frame_alloc,
        ).unwrap();

        let action = hyp.handle(
            TrapEvent::WfiWfe,
            &mut frame_alloc,
        ).unwrap();
        assert!(matches!(action, HypervisorAction::HvcResult { .. }));
    }

    #[test]
    fn smc_forward() {
        let mut hyp = make_hypervisor();
        let mut alloc = BumpAlloc::new(0x10_0000, 0x10_0000);
        let action = hyp.handle(
            TrapEvent::SmcForward { x0: 0xC400_0003, x1: 0, x2: 0, x3: 0 },
            &mut || alloc.alloc(),
        ).unwrap();
        assert!(matches!(action, HypervisorAction::ForwardSmc { x0: 0xC400_0003, .. }));
    }

    #[test]
    fn guest_exit_hvc_halts() {
        let mut hyp = make_hypervisor();
        let arena = vec![0u8; 64 * 4096];
        let arena_base = arena.as_ptr() as u64;
        let mut bump = arena_base;
        let mut frame_alloc = || {
            if bump >= arena_base + arena.len() as u64 { return None; }
            let addr = bump;
            bump += 4096;
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, 4096); }
            Some(PhysAddr(addr))
        };

        hyp.handle(
            TrapEvent::HvcCall { x0: HVC_VM_CREATE, x1: 0, x2: 0, x3: 0 },
            &mut frame_alloc,
        ).unwrap();
        hyp.handle(
            TrapEvent::HvcCall { x0: HVC_VM_START, x1: 1, x2: 0x4000_0000, x3: 0 },
            &mut frame_alloc,
        ).unwrap();

        let action = hyp.handle(
            TrapEvent::HvcCall { x0: HVC_GUEST_EXIT, x1: 0, x2: 0, x3: 0 },
            &mut frame_alloc,
        ).unwrap();
        assert!(matches!(action, HypervisorAction::HvcResult { x0: 0 }));
    }

    #[test]
    fn ping_returns_pong() {
        let mut hyp = make_hypervisor();
        let mut alloc = BumpAlloc::new(0x10_0000, 0x10_0000);
        let action = hyp.handle(
            TrapEvent::HvcCall { x0: crate::platform::HVC_PING, x1: 0, x2: 0, x3: 0 },
            &mut || alloc.alloc(),
        ).unwrap();
        assert_eq!(action, HypervisorAction::HvcResult { x0: crate::platform::HVC_PONG });
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-hypervisor`
Expected: Compilation error — `hypervisor` module doesn't exist

- [ ] **Step 3: Implement Hypervisor state machine**

```rust
// crates/harmony-hypervisor/src/hypervisor.rs
// SPDX-License-Identifier: GPL-2.0-or-later
//! Sans-I/O hypervisor state machine.
//!
//! Accepts `TrapEvent`s, returns `HypervisorAction`s. No register access,
//! no assembly — pure Rust logic testable with `cargo test`.

use alloc::collections::BTreeMap;

use crate::platform::{HVC_PING, HVC_PONG, VIRTUAL_UART_IPA};
use crate::stage2::Stage2PageTable;
use crate::trap::*;
use crate::vcpu::{Vm, VmState, VCpuContext};
use crate::vmid::{VmId, VmIdAllocator};
use harmony_microkernel::vm::PhysAddr;

/// The hypervisor state machine.
pub struct Hypervisor {
    vmid_alloc: VmIdAllocator,
    vms: BTreeMap<u8, Vm>,
    /// Currently executing VM (None = host).
    pub(crate) active_vmid: Option<VmId>,
    /// Host vCPU context (VM 0).
    host_ctx: VCpuContext,
    /// Converts PA → writable pointer (for Stage-2 table manipulation).
    phys_to_virt: fn(PhysAddr) -> *mut u8,
}

impl Hypervisor {
    pub fn new(phys_to_virt: fn(PhysAddr) -> *mut u8) -> Self {
        Self {
            vmid_alloc: VmIdAllocator::new(),
            vms: BTreeMap::new(),
            active_vmid: None,
            host_ctx: VCpuContext::default(),
            phys_to_virt,
        }
    }

    /// Process a trap event. Returns a single action for the platform shim.
    pub fn handle(
        &mut self,
        event: TrapEvent,
        frame_alloc: &mut dyn FnMut() -> Option<PhysAddr>,
    ) -> Result<HypervisorAction, HypervisorError> {
        match event {
            TrapEvent::HvcCall { x0, x1, x2, x3 } => self.handle_hvc(x0, x1, x2, x3, frame_alloc),
            TrapEvent::DataAbort { ipa, access, .. } => self.handle_data_abort(ipa, access),
            TrapEvent::InstructionAbort { ipa: _ } => {
                // Instruction fetch from unmapped IPA — kill the guest.
                let vmid = self.active_vmid.unwrap_or(VmId(0));
                Ok(HypervisorAction::DestroyVm { vmid })
            }
            TrapEvent::WfiWfe => {
                // Guest halted — return to host.
                if let Some(vmid) = self.active_vmid {
                    if let Some(vm) = self.vms.get_mut(&vmid.0) {
                        vm.state = VmState::Halted;
                    }
                    self.active_vmid = None;
                }
                // Return exit code 0 to host (guest halted normally).
                Ok(HypervisorAction::HvcResult { x0: 0 })
            }
            TrapEvent::SmcForward { x0, x1, x2, x3 } => {
                Ok(HypervisorAction::ForwardSmc { x0, x1, x2, x3 })
            }
        }
    }

    fn handle_hvc(
        &mut self,
        x0: u64,
        x1: u64,
        x2: u64,
        x3: u64,
        frame_alloc: &mut dyn FnMut() -> Option<PhysAddr>,
    ) -> Result<HypervisorAction, HypervisorError> {
        match x0 {
            HVC_VM_CREATE => self.hvc_vm_create(frame_alloc),
            HVC_VM_DESTROY => self.hvc_vm_destroy(x1),
            HVC_VM_START => self.hvc_vm_start(x1, x2),
            HVC_VM_MAP => self.hvc_vm_map(x1, x2, x3, frame_alloc),
            HVC_GUEST_EXIT => self.hvc_guest_exit(x1),
            HVC_PING => Ok(HypervisorAction::HvcResult { x0: HVC_PONG }),
            _ => Err(HypervisorError::InvalidHvc(x0)),
        }
    }

    fn hvc_vm_create(
        &mut self,
        frame_alloc: &mut dyn FnMut() -> Option<PhysAddr>,
    ) -> Result<HypervisorAction, HypervisorError> {
        let vmid = self.vmid_alloc.alloc().ok_or(HypervisorError::VmLimitReached)?;
        let root = frame_alloc().ok_or(HypervisorError::OutOfMemory)?;
        // Zero the root frame.
        let ptr = (self.phys_to_virt)(root);
        unsafe { core::ptr::write_bytes(ptr, 0, 4096); }

        let stage2 = Stage2PageTable::new(root, vmid, self.phys_to_virt);
        let vm = Vm {
            id: vmid,
            vcpu: VCpuContext::default(),
            stage2,
            state: VmState::Created,
        };
        self.vms.insert(vmid.0, vm);
        Ok(HypervisorAction::HvcResult { x0: vmid.0 as u64 })
    }

    fn hvc_vm_destroy(&mut self, x1: u64) -> Result<HypervisorAction, HypervisorError> {
        let vmid = VmId(x1 as u8);
        if self.vms.remove(&vmid.0).is_none() {
            return Err(HypervisorError::InvalidVmId(vmid));
        }
        self.vmid_alloc.free(vmid);
        if self.active_vmid == Some(vmid) {
            self.active_vmid = None;
        }
        Ok(HypervisorAction::HvcResult { x0: 0 })
    }

    fn hvc_vm_start(
        &mut self,
        x1: u64,
        x2: u64,
    ) -> Result<HypervisorAction, HypervisorError> {
        let vmid = VmId(x1 as u8);
        let entry_ipa = x2;
        let vm = self.vms.get_mut(&vmid.0).ok_or(HypervisorError::InvalidVmId(vmid))?;
        if vm.state == VmState::Running {
            return Err(HypervisorError::VmAlreadyRunning(vmid));
        }
        vm.vcpu.elr_el2 = entry_ipa;
        // SPSR_EL2 = EL1h (0b0101) + DAIF masked (0x3C0)
        vm.vcpu.spsr_el2 = 0x3C5;
        vm.state = VmState::Running;
        self.active_vmid = Some(vmid);
        Ok(HypervisorAction::EnterGuest { vmid })
    }

    fn hvc_vm_map(
        &mut self,
        x1: u64,
        x2: u64,
        x3: u64,
        frame_alloc: &mut dyn FnMut() -> Option<PhysAddr>,
    ) -> Result<HypervisorAction, HypervisorError> {
        let (vmid_raw, flags_raw, page_count) = unpack_vm_map_x1(x1);
        let vmid = VmId(vmid_raw);
        let ipa_base = x2;
        let pa_base = x3;

        let flags = Stage2Flags {
            readable: flags_raw & 0b001 != 0,
            writable: flags_raw & 0b010 != 0,
            executable: flags_raw & 0b100 != 0,
            mem_attr: match (flags_raw >> 3) & 0b111 {
                1 => Stage2MemAttr::NormalNonCacheable,
                2 => Stage2MemAttr::Device,
                _ => Stage2MemAttr::NormalWriteBack,
            },
        };

        let vm = self.vms.get_mut(&vmid.0).ok_or(HypervisorError::InvalidVmId(vmid))?;
        for i in 0..page_count as u64 {
            let ipa = ipa_base + i * 4096;
            let pa = PhysAddr(pa_base + i * 4096);
            vm.stage2.map(ipa, pa, flags, frame_alloc)
                .map_err(HypervisorError::Stage2MapFailed)?;
        }
        Ok(HypervisorAction::HvcResult { x0: 0 })
    }

    fn hvc_guest_exit(&mut self, x1: u64) -> Result<HypervisorAction, HypervisorError> {
        if let Some(vmid) = self.active_vmid {
            if let Some(vm) = self.vms.get_mut(&vmid.0) {
                vm.state = VmState::Halted;
            }
            self.active_vmid = None;
        }
        Ok(HypervisorAction::HvcResult { x0: x1 })
    }

    fn handle_data_abort(
        &self,
        ipa: u64,
        access: AccessType,
    ) -> Result<HypervisorAction, HypervisorError> {
        if ipa == VIRTUAL_UART_IPA {
            let ch = match access {
                AccessType::Write { value } => value as u8,
                AccessType::Read => 0, // Read from UART returns 0
            };
            return Ok(HypervisorAction::EmitChar { ch });
        }
        // Unknown IPA — kill the guest.
        let vmid = self.active_vmid.unwrap_or(VmId(0));
        Ok(HypervisorAction::DestroyVm { vmid })
    }
}
```

Update `src/lib.rs` to add `pub mod hypervisor;`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p harmony-hypervisor`
Expected: All tests pass

- [ ] **Step 5: Run workspace-wide checks**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: Clean

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-hypervisor/src/hypervisor.rs crates/harmony-hypervisor/src/lib.rs
git commit -m "feat(hypervisor): add Hypervisor state machine (sans-I/O core)"
```

---

## Task 7: Full VM lifecycle integration test

**Files:**
- Modify: `crates/harmony-hypervisor/src/hypervisor.rs` (add integration-style test)

**Context:**
- This test simulates the complete guest stub flow: create → map → start → UART write traps → guest exit
- Validates the entire sans-I/O path end-to-end without hardware
- Uses the same BumpAlloc + heap arena pattern from Task 6

- [ ] **Step 1: Write the integration test**

Add to the existing `tests` module in `hypervisor.rs`:

```rust
    #[test]
    fn full_guest_stub_lifecycle() {
        let arena = vec![0u8; 128 * 4096];
        let arena_base = arena.as_ptr() as u64;
        let mut bump = arena_base;
        let mut frame_alloc = || {
            if bump >= arena_base + arena.len() as u64 { return None; }
            let addr = bump;
            bump += 4096;
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, 4096); }
            Some(PhysAddr(addr))
        };

        let mut hyp = Hypervisor::new(|pa| pa.0 as *mut u8);

        // 1. Create VM
        let action = hyp.handle(
            TrapEvent::HvcCall { x0: HVC_VM_CREATE, x1: 0, x2: 0, x3: 0 },
            &mut frame_alloc,
        ).unwrap();
        let vmid = match action {
            HypervisorAction::HvcResult { x0 } => x0 as u8,
            _ => panic!("expected HvcResult"),
        };
        assert_eq!(vmid, 1);

        // 2. Map 8 pages of guest RAM at IPA 0x4000_0000
        let x1 = pack_vm_map_x1(vmid, 0b00_000_111, 8); // RWX, WriteBack, 8 pages
        let action = hyp.handle(
            TrapEvent::HvcCall { x0: HVC_VM_MAP, x1, x2: 0x4000_0000, x3: 0xA000_0000 },
            &mut frame_alloc,
        ).unwrap();
        assert!(matches!(action, HypervisorAction::HvcResult { x0: 0 }));

        // 3. Start VM at entry IPA
        let action = hyp.handle(
            TrapEvent::HvcCall { x0: HVC_VM_START, x1: vmid as u64, x2: 0x4000_0000, x3: 0 },
            &mut frame_alloc,
        ).unwrap();
        assert!(matches!(action, HypervisorAction::EnterGuest { vmid: VmId(1) }));

        // 4. Guest writes "Hi" to virtual UART
        let message = b"Hi";
        for &ch in message {
            let action = hyp.handle(
                TrapEvent::DataAbort {
                    ipa: VIRTUAL_UART_IPA,
                    access: AccessType::Write { value: ch as u64 },
                    width: 1,
                },
                &mut frame_alloc,
            ).unwrap();
            assert_eq!(action, HypervisorAction::EmitChar { ch });
        }

        // 5. Guest exits via HVC
        let action = hyp.handle(
            TrapEvent::HvcCall { x0: HVC_GUEST_EXIT, x1: 0, x2: 0, x3: 0 },
            &mut frame_alloc,
        ).unwrap();
        assert_eq!(action, HypervisorAction::HvcResult { x0: 0 });

        // 6. Destroy VM
        let action = hyp.handle(
            TrapEvent::HvcCall { x0: HVC_VM_DESTROY, x1: vmid as u64, x2: 0, x3: 0 },
            &mut frame_alloc,
        ).unwrap();
        assert_eq!(action, HypervisorAction::HvcResult { x0: 0 });
    }
```

- [ ] **Step 2: Run test to verify it passes**

Run: `cargo test -p harmony-hypervisor full_guest_stub_lifecycle`
Expected: PASS

- [ ] **Step 3: Run workspace-wide checks**

Run: `cargo clippy --workspace --all-targets && cargo test --workspace`
Expected: Clean

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-hypervisor/src/hypervisor.rs
git commit -m "test(hypervisor): add full guest stub lifecycle integration test"
```

---

## Dependencies

```
Task 1 (scaffold + VmId)
  ↓
Task 2 (trap types) ← depends on Task 1 (VmId)
  ↓
Task 3 (Stage-2 page table) ← depends on Task 2 (Stage2Flags)
  ↓
Task 4 (vCPU context) ← depends on Task 3 (Stage2PageTable)
  ↓
Task 5 (platform constants) ← depends on Task 1 (standalone)
  ↓
Task 6 (Hypervisor state machine) ← depends on Tasks 2-5
  ↓
Task 7 (lifecycle integration test) ← depends on Task 6
```

Tasks 1-5 build up the type system. Task 6 is the main brain that composes them all. Task 7 is the end-to-end validation.
