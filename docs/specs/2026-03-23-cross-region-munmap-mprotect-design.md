# Cross-Region munmap/mprotect (harmony-os-b7h)

Extend `unmap_partial` and `protect_partial` to span multiple regions.
Currently these operations require the target range to fall within a
single region. Full Linux semantics allow any page-aligned range that
may overlap multiple regions — unmapping the middle splits one, removes
intermediates, and splits another.

## Context

The existing `find_containing_region` helper returns an error if the
target range isn't fully contained in one region. Real programs
(ELF loaders, aggressive allocators, libc `free` implementations)
routinely call `munmap`/`mprotect` on ranges that span multiple
regions or include unmapped gaps. Without cross-region support, these
calls fail with EINVAL/NotMapped.

## Design

### Algorithm

Given a target range `[vaddr, vaddr+len)`:

1. **Collect overlapping regions** — scan the `BTreeMap<VirtAddr, Region>`
   for any region whose range intersects the target. A region at `base`
   with length `rlen` overlaps if `base < vaddr+len && base+rlen > vaddr`.
   Collect the base addresses first (to avoid borrowing conflicts during
   mutation).

2. **For each overlapping region**, compute the intersection:
   - `overlap_start = max(base, vaddr)`
   - `overlap_end = min(base+rlen, vaddr+len)`

3. **Unmap:** remove the region from the map, partition frames into
   before/overlap/after. Free overlap frames, unmap from page table,
   re-insert surviving before/after regions.

4. **Protect:** update page table flags for overlap pages, remove the
   region, partition frames, re-insert up to three regions (before with
   old flags, overlap with new flags, after with old flags).

### Unmapped Gaps

Linux `munmap` and `mprotect` silently ignore pages in the target range
that aren't mapped. The cross-region iteration naturally handles this —
we only process regions that overlap the target. Pages between regions
(gaps) are not touched.

### Error Handling

`protect_partial` updates page table flags before modifying the region
map (existing pattern). If `set_flags` fails on any page, the operation
returns an error with some pages already updated — matching the existing
single-region behavior. In practice, `set_flags` only fails for
unmapped pages, which we've already verified are mapped by checking
region membership.

For `unmap_partial`, failures during frame freeing are silently ignored
(existing pattern — `let _ = buddy.free_frame()`).

### Validation

Both operations validate:
- `len > 0` (existing)
- `vaddr` and `len` page-aligned (existing)
- Process exists (existing)

No error for "no overlapping regions found" — an empty overlap set
means nothing to do, return `Ok(())`. This matches Linux behavior
where `munmap` on unmapped memory succeeds.

### find_containing_region

`find_containing_region` is preserved unchanged — it's used by the
kernel's `vm_protect_partial` wrapper for Lyll/Nakaiah guardian checks
and by other callers that need single-region semantics. The cross-region
logic is implemented directly in `unmap_partial` and `protect_partial`
without using this helper.

### Kernel Wrapper Changes

`vm_unmap_partial` in `kernel.rs` currently uses `find_containing_region`
to pre-check guardian classifications. For cross-region support, it needs
to iterate over all overlapping regions and check each one's classification.

`vm_protect_partial` in `kernel.rs` currently uses `find_containing_region`
to check writable transitions (Lyll/Nakaiah guardians). For cross-region
support, it needs to check each overlapping region's flags.

### No Linuxulator Changes

`sys_munmap` and `sys_mprotect` already delegate to `backend.vm_munmap`
/ `backend.vm_mprotect`, which call through to the kernel wrappers.
The cross-region behavior is transparent to the Linuxulator.

## File Changes

**`crates/harmony-microkernel/src/vm/manager.rs`:**
- `unmap_partial`: rewrite to iterate overlapping regions instead of
  requiring `find_containing_region`
- `protect_partial`: rewrite to iterate overlapping regions
- Add helper to collect overlapping region base addresses
- ~7 new tests for cross-region scenarios

**`crates/harmony-microkernel/src/kernel.rs`:**
- `vm_unmap_partial`: iterate overlapping regions for guardian checks
- `vm_protect_partial`: iterate overlapping regions for writable checks

## Test Plan

| Test | Behavior verified |
|------|-------------------|
| unmap_spanning_two_regions | Range spans two adjacent regions → both partially unmapped, survivors correct |
| unmap_covering_middle_region | Range fully covers middle region + partial edges → middle removed, edges split |
| unmap_with_gap | Range includes unmapped gap between regions → gap silently skipped |
| unmap_entire_two_regions | Range exactly covers two regions → both fully removed |
| unmap_no_overlap | Range is entirely unmapped → Ok(()) returned |
| protect_spanning_two_regions | Range spans two regions → flags updated on overlap portions |
| protect_with_gap | Range includes unmapped gap → only mapped portions affected |
| protect_spanning_three_regions | Range spans three regions → all three split/updated |

All existing single-region tests must continue to pass unchanged.

## Dependencies

| Bead | Relationship |
|------|-------------|
| harmony-os-a2o | Prerequisite (closed) — single-region partial ops |
