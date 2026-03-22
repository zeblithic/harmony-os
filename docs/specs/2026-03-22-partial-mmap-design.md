# Partial munmap/mprotect for Sub-Ranges (harmony-os-a2o)

Add region-splitting support to AddressSpaceManager so munmap and
mprotect can operate on sub-ranges within a single region. Required
for ELF loaders that split mapped segments into .text (RX) and
.data (RW), and for unmapping over-mapped BSS sections.

## Context

The AddressSpaceManager tracks memory regions in a
`BTreeMap<VirtAddr, Region>`. Each region is currently all-or-nothing:
`unmap_region` removes the entire entry, `protect_region` changes
flags on all pages uniformly. The `len` parameter passed through
from sys_munmap/sys_mprotect is ignored.

ELF loaders need:
- **Partial mprotect:** Map a segment as RW, write data, then
  mprotect .text portion to RX while keeping .data as RW
- **Partial munmap:** Unmap the tail of an over-mapped segment
  (BSS beyond file data)

Without region splitting, dynamically-linked NixOS binaries cannot
load correctly.

## Design

### Scope: Single-Region Operations

Both operations require the target range `[vaddr, vaddr+len)` to be
fully contained within a single existing region. Cross-region
operations (spanning multiple regions) return `NotMapped` and are
deferred to a follow-up bead (harmony-os-b7h).

### unmap_partial(pid, vaddr, len)

Finds the region containing `[vaddr, vaddr+len)`. Three cases:

1. **Exact match** (vaddr == base, len == region.len):
   Remove entire region. Free all frames, unmap all pages.

2. **Prefix or suffix removal** (range touches one boundary):
   - Prefix: remove first N pages. Region starts at `vaddr+len`.
   - Suffix: remove last N pages. Region shrinks.
   - Free removed frames, unmap removed pages.
   - Update the single remaining region in the BTreeMap.

3. **Hole punch** (range is in the middle):
   - Split into two regions: `[base, vaddr)` and `[vaddr+len, end)`.
   - Free middle frames, unmap middle pages.
   - Remove original region, insert two new regions.

### protect_partial(pid, vaddr, len, new_flags)

Finds the region containing `[vaddr, vaddr+len)`. Three cases:

1. **Exact match**: Change flags on entire region. Update all page
   table entries.

2. **Prefix or suffix**: Split into two regions with different flags.
   Update page table entries for the changed pages.

3. **Middle sub-range**: Split into three regions:
   `[base, vaddr)` with original flags, `[vaddr, vaddr+len)` with
   new flags, `[vaddr+len, end)` with original flags. Update page
   table entries for the middle pages.

### Splitting Mechanics

The `Region` struct is unchanged:

```rust
pub struct Region {
    pub len: usize,
    pub flags: PageFlags,
    pub classification: FrameClassification,
    pub frames: Vec<PhysAddr>,
}
```

Splitting partitions the `frames` vec by page index:
- `page_offset = (vaddr - region_base) / PAGE_SIZE`
- `page_count = len / PAGE_SIZE`
- Before: `frames[..page_offset]`
- Target: `frames[page_offset..page_offset+page_count]`
- After: `frames[page_offset+page_count..]`

For unmap: target frames are freed via buddy allocator and unmapped
from the page table. For protect: target pages get new flags via
`page_table.set_flags()`.

Frame ownership transfers cleanly — `Vec::split_off` and
`Vec::drain` move frames without cloning.

### Backward Compatibility

Existing `unmap_region(pid, vaddr)` and `protect_region(pid, vaddr,
new_flags)` become thin wrappers:
- `unmap_region` looks up the region length, calls `unmap_partial`
- `protect_region` looks up the region length, calls `protect_partial`

No callers need to change. The old exact-match behavior is preserved
as case 1 of each new method.

### Validation

Both operations validate:
- `vaddr` is page-aligned
- `len` is page-aligned and > 0
- `[vaddr, vaddr+len)` is fully contained within one region
- Returns `VmError::NotMapped` if no containing region found

### No SyscallBackend Changes

The existing `vm_munmap(vaddr, len)` and `vm_mprotect(vaddr, len,
flags)` signatures already accept the `len` parameter. The
Linuxulator already passes the correct `len`. The fix is entirely
inside `AddressSpaceManager` — making it respect the `len` parameter
that was previously ignored.

### Kernel Layer (kernel.rs)

`Kernel::vm_unmap_region(pid, vaddr)` currently clones the region's
frames before unmapping (for Lyll/Nakaiah guardian unregistration).
The new partial variant needs the same pattern:

`Kernel::vm_unmap_partial(pid, vaddr, len)`:
1. Look up the containing region to identify which frames are being freed
2. Compute the frame slice for `[vaddr, vaddr+len)` only
3. Call `AddressSpaceManager::unmap_partial(pid, vaddr, len)`
4. Unregister the freed frames from Lyll and Nakaiah guardians

`Kernel::vm_protect_partial(pid, vaddr, len, new_flags)`:
1. Check if the target pages were non-writable and are becoming writable
2. Call `AddressSpaceManager::protect_partial(pid, vaddr, len, new_flags)`
3. If transitioning to writable, promote affected frames from
   CidBacked → Snapshot in Lyll

The existing `vm_unmap_region` and `vm_protect_region` become wrappers
that look up the full region length and delegate to the partial methods.

### KernelBackend (linuxulator.rs)

`KernelBackend::vm_munmap` currently has `let _ = len;` and ignores
the length. Update to pass `len` through to `Kernel::vm_unmap_partial`.

`KernelBackend::vm_mprotect` currently ignores `_len`. Update to
pass `len` through to `Kernel::vm_protect_partial`.

### Budget and Guardian Interactions

When `unmap_partial` frees frames, the buddy allocator reclaims them
and CapTracker's budget is updated automatically via the existing
`remove_mapping` path in the manager. No changes needed.

`destroy_space` iterates all regions in the BTreeMap — splitting
creates more entries but the iteration handles any count. No changes.

## File Changes

| File | Changes |
|------|---------|
| `crates/harmony-microkernel/src/vm/manager.rs` | Add `unmap_partial`, `protect_partial`. Refactor `unmap_region` and `protect_region` to delegate. 9 unit tests. |
| `crates/harmony-microkernel/src/kernel.rs` | Add `vm_unmap_partial`, `vm_protect_partial` with guardian integration. Refactor existing methods to delegate. |
| `crates/harmony-os/src/linuxulator.rs` | Update `KernelBackend::vm_munmap` and `vm_mprotect` to pass `len` through. 2 integration tests. |

## Test Plan

**Manager-level tests** (MockPageTable, in manager.rs):

| Test | Behavior verified |
|------|-------------------|
| test_unmap_partial_exact | Full region unmap (backward compat) |
| test_unmap_partial_prefix | Remove first N pages, region starts at vaddr+len |
| test_unmap_partial_suffix | Remove last N pages, region shrinks |
| test_unmap_partial_middle | Hole punch — one region becomes two |
| test_unmap_partial_not_contained | Range beyond region → NotMapped |
| test_unmap_partial_frees_frames | Buddy allocator reclaims exactly the partial page count |
| test_unmap_partial_unaligned | Unaligned vaddr or len → Unaligned error |
| test_protect_partial_exact | Full region protect (backward compat) |
| test_protect_partial_prefix | First N pages get new flags |
| test_protect_partial_suffix | Last N pages changed |
| test_protect_partial_middle | Middle changed — three regions |
| test_protect_partial_not_contained | Range beyond region → NotMapped |

**Linuxulator-level tests** (VmMockBackend, in linuxulator.rs):

| Test | Behavior verified |
|------|-------------------|
| test_mprotect_sub_range | mmap + mprotect sub-range passes through correctly |
| test_munmap_sub_range | mmap + munmap sub-range passes through correctly |

## Dependencies

| Bead | Relationship |
|------|-------------|
| harmony-os-b7h | Follow-up — cross-region munmap/mprotect |
| harmony-os-hbe | Parent — syscall coverage umbrella |
