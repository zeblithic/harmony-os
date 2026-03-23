# Page Table Intermediate Frame Freeing

**Bead:** harmony-os-er2
**Date:** 2026-03-23
**Status:** Draft

## Problem

When `unmap` removes a leaf mapping, intermediate page table frames (L0-L2 on
aarch64, PML4-PD on x86_64) are never freed. Over time, repeated map/unmap
cycles leak physical frames. On RPi5 with limited RAM (1-8 GB), this leads to
eventual OOM. The buddy allocator supports `free_frame()` but `unmap` has no
mechanism to return intermediate frames.

## Solution

Add a `frame_dealloc` callback to `PageTable::unmap`. After removing the leaf
entry, the implementation walks back up the tree and prunes empty intermediate
tables — if all entries in a table are invalid (no valid/present bit set), the
frame is freed via the callback and the parent's entry is cleared.

## Design Decisions

### Dealloc callback mirrors alloc callback (symmetric design)

`map` already takes `frame_alloc: &mut dyn FnMut() -> Option<PhysAddr>`.
`unmap` now takes `frame_dealloc: &mut dyn FnMut(PhysAddr)`. Symmetric
interface: map allocates, unmap deallocates. Same callback pattern the
codebase already uses.

The callback is infallible (`-> ()`). Callers that forward to
`buddy.free_frame()` discard the error with `let _ =`, matching the
existing pattern in the manager's map-error rollback path.

### Scan-and-prune, not reference counting

Checking if a 512-entry table is empty requires scanning all entries — O(512)
per level per unmap. An alternative is reference counting each intermediate
table. Scanning is simpler, has no per-entry storage overhead, and is fast
enough for this hardware. If profiling shows it's a bottleneck, reference
counts can be added later.

### Bottom-up pruning (leaf toward root, stopping before root)

After clearing the leaf, walk from the leaf table back toward the root. At
each non-leaf, non-root level, check if the table is empty. If so, free it
and clear the parent entry, then continue up. If non-empty, stop — all
ancestors are also non-empty.

**The root table (L0 on aarch64, PML4 on x86_64) is never freed.** It lives
for the lifetime of the address space. The upward walk stops one level below
the root.

## Architecture

### Trait Change

```rust
// page_table.rs
pub trait PageTable {
    fn unmap(
        &mut self,
        vaddr: VirtAddr,
        frame_dealloc: &mut dyn FnMut(PhysAddr),
    ) -> Result<PhysAddr, VmError>;

    // map, set_flags, translate, activate, root_paddr unchanged
}
```

### Implementation (aarch64 and x86_64)

After clearing the leaf descriptor:

```
walk back from leaf table toward root (skip root):
    if is_table_empty(table):
        frame_dealloc(table_frame_addr)
        clear parent's entry pointing to this table
    else:
        break  // non-empty table means all ancestors are also non-empty
```

`is_table_empty` checks validity bits, not raw zero:
- aarch64: `table.iter().all(|&e| e & 0b11 == 0)` (valid bit in [1:0])
- x86_64: `table.iter().all(|&e| e & PTE_PRESENT == 0)`

In practice, cleared entries are zero (both `map` and `unmap` write 0 to
clear entries), so checking for zero is equivalent. But using the valid/present
bit check is more correct and explicit.

### MockPageTable

Accepts and ignores the callback — `MockPageTable` doesn't model intermediate
tables, so there's nothing to free.

### VM Manager Integration

`unmap_region` and `destroy_space` pass the buddy allocator's `free_frame` as
the callback:

```rust
let freed_paddr = space.page_table.unmap(vaddr, &mut |frame| {
    let _ = buddy.free_frame(frame);
})?;
```

### Boot Crate Callers

Any direct `page_table.unmap()` calls in the boot crates pass a no-op
callback (boot crates use a bump allocator that doesn't support freeing).
Verified: no current `unmap` calls exist in either boot crate.

## File Changes

| File | Change |
|------|--------|
| `crates/harmony-microkernel/src/vm/page_table.rs` | Change `unmap` signature to include `frame_dealloc` |
| `crates/harmony-microkernel/src/vm/aarch64.rs` | Bottom-up prune after leaf removal + `is_table_empty` helper |
| `crates/harmony-microkernel/src/vm/x86_64.rs` | Same prune logic for x86_64 levels |
| `crates/harmony-microkernel/src/vm/mock.rs` | Accept and ignore `frame_dealloc` callback |
| `crates/harmony-microkernel/src/vm/manager.rs` | Pass `buddy.free_frame` in `unmap_region` and `destroy_space` |

## What is NOT in Scope

- No reference counting on intermediate tables (scan-and-prune is sufficient)
- No changes to `map` (allocation side works correctly)
- No changes to the buddy allocator itself
- No TLB invalidation changes (the existing unmap path handles TLB)
- No boot crate changes (verified: no `unmap` calls in boot crates)

## Testing

Arch-specific integration tests (using real `Aarch64PageTable` / `X86_64PageTable`
with heap-backed arenas — the existing test infrastructure):

- `unmap_prunes_empty_intermediate` — map one page, unmap it, verify all intermediate frames freed (counting allocator tracks alloc/free counts)
- `unmap_preserves_sibling_intermediates` — map two pages sharing an intermediate table, unmap one, verify intermediate NOT freed
- `unmap_frees_chain` — map one page deep in the tree, unmap it, verify all intermediate levels freed

Manager-level test update:
- `unmap_frees_frames` uses `MockPageTable` which doesn't model intermediates — this test verifies data frame freeing only. Intermediate frame freeing is verified by the arch-specific tests above.
