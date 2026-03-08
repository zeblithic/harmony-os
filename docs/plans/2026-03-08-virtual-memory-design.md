# Ring 2: Virtual Memory and Page Tables — Design

**Date:** 2026-03-08
**Status:** Approved
**Bead:** harmony-qv2

## Problem

Ring 2's process isolation is currently cooperative — processes are separated by 9P IPC trait-object boundaries, but share a single flat address space. Any process can corrupt another's memory. Hardware page tables are required to enforce real isolation, support Linux binary compatibility (mmap/munmap), and provide defense-in-depth alongside the capability system.

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Architecture targets | x86_64 + aarch64 simultaneously | Developing both validates the abstraction; ARM's TTBR0/TTBR1 split and permission model differ enough to catch x86-isms early |
| Page granularity | 4 KiB only | Matches Athenaeum chunk size (1:1 CID→page mapping). Huge pages are a future optimization |
| Physical frame allocator | Buddy allocator (order 0–10) | O(log n) alloc/free, natural coalescing, design doc specifies it |
| Kernel mapping | Higher-half (0xFFFF_8000_0000_0000+) | Avoids full page table swap on syscall. aarch64's TTBR0/TTBR1 is designed for this split |
| Capability model | Full per-frame MemoryCap | Defense-in-depth: every frame has a capability chain. You can't recover from a data breach — so prevent it at the hardware level |
| Frame metadata | Hybrid: bitmap + B-tree | Bitmap for alloc/free (O(1)), B-tree only for "interesting" frames (shared, encrypted, ephemeral). Keeps overhead proportional to special frames, not total RAM |
| Code structure | Layered: PageTable trait + AddressSpaceManager | Sans-I/O pattern applied to memory management. ~90% of logic testable on host with MockPageTable |
| Linuxulator integration | Budget-based MemoryCap with per-mapping tracking | Transparent to Linux binaries (POSIX mmap semantics), capability-enforced underneath |
| Scope | Full stack including Linuxulator wiring | End-to-end: trait + both arch impls + buddy + caps + mmap/munmap |

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Linuxulator                           │
│            mmap() / munmap() / mprotect()                │
└────────────────────────┬─────────────────────────────────┘
                         │ syscall
┌────────────────────────▼─────────────────────────────────┐
│              AddressSpaceManager<P: PageTable>           │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐  │
│  │ BuddyAlloc   │ │ CapTracker   │ │ MappingTable     │  │
│  │ (phys frames)│ │ (B-tree +    │ │ (per-process     │  │
│  │              │ │  bitmap)     │ │  vaddr→paddr)    │  │
│  └──────────────┘ └──────────────┘ └──────────────────┘  │
└────────────────────────┬─────────────────────────────────┘
                         │ PageTable trait
           ┌─────────────┴──────────────┐
           ▼                            ▼
┌───────────────────┐       ┌───────────────────┐
│ x86_64 PageTable  │       │ aarch64 PageTable  │
│ (PML4/PDP/PD/PT)  │       │ (TTBR0/1, 4-lvl)  │
│ CR3 management    │       │ translation tbl    │
└───────────────────┘       └───────────────────┘
```

## PageTable Trait

The hardware boundary. Implementors manipulate MMU state only — no policy, no allocation decisions, no capability checks.

```rust
pub trait PageTable {
    type Error: core::fmt::Debug;

    fn map(&mut self, vaddr: VirtAddr, paddr: PhysAddr, flags: PageFlags)
        -> Result<(), Self::Error>;
    fn unmap(&mut self, vaddr: VirtAddr) -> Result<PhysAddr, Self::Error>;
    fn set_flags(&mut self, vaddr: VirtAddr, flags: PageFlags)
        -> Result<(), Self::Error>;
    fn translate(&self, vaddr: VirtAddr) -> Option<(PhysAddr, PageFlags)>;
    fn activate(&self);
    fn root_paddr(&self) -> PhysAddr;
}
```

### Types

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtAddr(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysAddr(pub u64);

bitflags! {
    pub struct PageFlags: u64 {
        const READABLE   = 1 << 0;
        const WRITABLE   = 1 << 1;
        const EXECUTABLE = 1 << 2;
        const USER       = 1 << 3;
        const NO_CACHE   = 1 << 4;
        const GLOBAL     = 1 << 5;
    }
}
```

### x86_64 Implementation

4-level paging: PML4 → PDP → PD → PT, each table 512 entries × 8 bytes = 4 KiB.

- `map()`: walks/allocates intermediate tables, sets PTE with translated flags (WRITABLE→bit 1, USER→bit 2, EXEC→clear NX bit 63)
- `activate()`: writes root frame to CR3
- Intermediate table frames allocated via `FnMut() -> Option<PhysAddr>` callback — keeps trait agnostic to the allocator

### aarch64 Implementation

4-level translation tables with 4 KiB granule: L0 → L1 → L2 → L3, same 512-entry structure.

- TTBR0_EL1 for user space (lower half), TTBR1_EL1 for kernel (upper half)
- Permission model uses AP bits + UXN/PXN (inverted vs x86_64 NX). PageFlags translation handles the mapping.
- `activate()`: writes TTBR0_EL1 only (TTBR1 stays fixed for kernel)

### MockPageTable

```rust
pub struct MockPageTable {
    mappings: BTreeMap<VirtAddr, (PhysAddr, PageFlags)>,
    root: PhysAddr,
}
```

In-memory map for host testing. ~80% of test coverage runs against this.

## Buddy Allocator

```rust
pub struct BuddyAllocator {
    free_lists: [Vec<PhysAddr>; MAX_ORDER + 1],  // Order 0 = 4 KiB .. order 10 = 4 MiB
    bitmap: Vec<u8>,                              // 1 bit per frame
    base: PhysAddr,
    frame_count: usize,
}
```

- **alloc(order)**: find smallest free block ≥ requested, split larger blocks down. O(MAX_ORDER) worst case.
- **free(addr, order)**: free block, coalesce with buddy (`addr XOR (1 << (order + 12))`). Recurse upward. O(MAX_ORDER) worst case.
- **Initialization**: receives memory map from bootloader, inserts usable regions as largest possible buddy blocks, marks reserved regions as allocated.

## Frame Classification and Capability Tracking

### Two Metadata Bits

Every frame has a 2-bit classification: `[encrypted][ephemeral]`.

| Bits | Meaning | Cache class | Unmap behavior |
|------|---------|-------------|----------------|
| `00` | Public, durable | LFU | Normal free |
| `01` | Public, ephemeral | LRU | Normal free |
| `10` | Encrypted, durable | LFU | Zeroize then free |
| `11` | Encrypted, ephemeral | LRU | Zeroize then free |

These bits come from the content-addressing layer — a CID-addressed chunk's leading bits encode sensitivity and intended durability.

### Hybrid Tracking

```rust
pub struct CapTracker {
    alloc_bitmap: Vec<u8>,                       // 1 bit per frame, O(1) alloc check
    frame_meta: BTreeMap<u32, FrameMeta>,         // Only "interesting" frames
    budgets: BTreeMap<u32, MemoryBudget>,          // Per-process limits
}

pub struct FrameMeta {
    owner_pid: u32,
    classification: FrameClassification,
    cap_token: UcanToken,
    mapped_by: SmallVec<u32, 2>,                  // Inline for ≤2 PIDs
}

pub struct MemoryBudget {
    limit: usize,
    used: usize,
    allowed_classes: FrameClassification,
}
```

**Default frames** (private, public, durable) don't get B-tree entries — ownership is implicit from the page table. Only shared, encrypted, or ephemeral frames get tracked. This keeps the B-tree small and proportional to special frames.

### Revocation Cascade

When a MemoryCap is revoked:

1. Find all frames in `frame_meta` whose `cap_token` matches or descends from the revoked token
2. For each frame, for each PID in `mapped_by`: unmap the page
3. If encrypted: zeroize frame contents
4. Free frames back to buddy allocator
5. Refund budget for affected processes

## AddressSpaceManager

The central coordinator. All policy lives here — the PageTable trait handles only hardware mechanics.

```rust
pub struct AddressSpaceManager<P: PageTable> {
    spaces: BTreeMap<u32, ProcessSpace<P>>,
    buddy: BuddyAllocator,
    cap_tracker: CapTracker,
    kernel_table: P,
}

pub struct ProcessSpace<P: PageTable> {
    page_table: P,
    regions: BTreeMap<VirtAddr, Region>,
}

pub struct Region {
    len: usize,
    flags: PageFlags,
    classification: FrameClassification,
    frames: Vec<PhysAddr>,
}
```

### Key Operations

- `create_space(pid, budget)` — new page table with kernel higher-half cloned
- `map_region(pid, vaddr, len, flags, classification, cap)` — allocate frames, check budget, write PTEs
- `unmap_region(pid, vaddr, len)` — unmap, zeroize if encrypted, free frames, refund budget
- `protect_region(pid, vaddr, len, flags)` — update page flags
- `destroy_space(pid)` — unmap everything, zeroize encrypted, free all frames
- `revoke_cap(token)` — cascading unmap across all affected processes
- `share_region(from, to, ...)` — grant shared mapping with delegated capability
- `switch_to(pid)` — activate page table for context switch

### Virtual Address Layout (per-process)

```
0x0000_0000_0000_0000  Guard page (null pointer trap)
0x0000_0000_0000_1000  User text (ELF segments)
                       User heap (grows ↑)
                       mmap regions
                       User stack (grows ↓)
0x0000_7FFF_FFFF_F000  Guard page
    ── canonical hole ──
0xFFFF_8000_0000_0000  Kernel (shared, GLOBAL flag)
                       Physical memory mapping
                       Kernel heap, kernel stacks
0xFFFF_FFFF_FFFF_FFFF
```

## Linuxulator Integration

### Syscall Updates

| Syscall | Before | After |
|---------|--------|-------|
| `mmap` | Returns `0x1_0000_0000` | Allocates frames, maps into page table, checks budget |
| `munmap` | Returns `0` (noop) | Unmaps, zeroizes encrypted, frees frames, refunds budget |
| `mprotect` | Returns `0` (noop) | Updates page flags via protect_region() |
| `brk` | Tracks pointer only | Expands/contracts heap with real mappings |

### ELF Loading

```
ELF parse → for each PT_LOAD segment:
    1. vm.map_region(pid, segment.vaddr, segment.memsz, flags, ...)
    2. Copy segment.filesz bytes into mapped pages
    3. Zero remaining (memsz - filesz) — BSS
    4. mprotect to final permissions
```

### Process Lifecycle

```
spawn_process(name, elf_binary, budget, classification)
  → Kernel::spawn_process() — PID, namespace, capabilities
  → vm.create_space(pid, budget) — page table + kernel half
  → Load ELF segments into address space
  → Map stack region at top of user space
  → Set entry point
  → process runs...
  → mmap/munmap/mprotect via Linuxulator
  → 9P IPC via kernel (unchanged)
  → process exits...
  → vm.destroy_space(pid) — unmap all, zeroize encrypted, free all
```

## Kernel Integration

The Kernel struct gains a type parameter:

```rust
pub struct Kernel<P: PageTable> {
    processes: BTreeMap<u32, Process>,
    // ... existing fields ...
    vm: AddressSpaceManager<P>,
}
```

Existing tests use `Kernel<MockPageTable>`. No regressions.

## Module Layout

```
harmony-microkernel/src/
    vm/
        mod.rs              — VirtAddr, PhysAddr, PageFlags, VmError
        page_table.rs       — PageTable trait
        x86_64.rs           — x86_64 4-level paging impl
        aarch64.rs          — aarch64 4-level translation table impl
        mock.rs             — MockPageTable (cfg(test))
        buddy.rs            — BuddyAllocator
        cap_tracker.rs      — CapTracker, FrameMeta, MemoryBudget
        manager.rs          — AddressSpaceManager<P>
    kernel.rs               — Kernel<P: PageTable> (updated)

harmony-os/src/
    linuxulator.rs          — mmap/munmap/mprotect/brk wired to real VM

harmony-boot/src/
    main.rs                 — Boot-time page table setup, CR3 switch
```

## Testing Strategy

### Layer 1: Host Unit Tests (~80 tests)

- **BuddyAllocator (~20)**: alloc/free, split, coalesce, exhaustion, fragmentation
- **CapTracker (~15)**: budget enforcement, classification, revocation cascade
- **AddressSpaceManager + MockPageTable (~30)**: full lifecycle, shared regions, encrypted zeroize
- **Region management (~10)**: find_free_region, overlap, partial munmap
- **PageFlags/PTE encoding (~10 per arch)**: bit translation round-trips

### Layer 2: Linuxulator Integration (~15 tests)

- mmap/munmap/mprotect through syscall dispatch
- ELF loading with real address spaces
- Budget exhaustion returns ENOMEM
- brk expansion/contraction

### Layer 3: QEMU Integration (~5 tests)

- Two processes with private pages can't read each other's
- Encrypted frame zeroized on munmap
- Process exit frees all frames
- hello.elf runs with real page tables

### Totals

| Category | Tests |
|----------|-------|
| New | ~105 |
| Existing (unchanged) | 191 |
| Grand total | ~296 |
