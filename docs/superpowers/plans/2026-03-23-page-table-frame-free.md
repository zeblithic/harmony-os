# Page Table Intermediate Frame Freeing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Free intermediate page table frames when unmap empties them, fixing a memory leak on repeated map/unmap cycles.

**Architecture:** Add `frame_dealloc` callback to `PageTable::unmap`. After clearing the leaf entry, both aarch64 and x86_64 implementations walk back up the tree and prune empty intermediate tables by calling the callback. The root table is never freed.

**Tech Stack:** Rust, harmony-microkernel (vm module: page_table trait, aarch64, x86_64, mock, manager)

**Spec:** `docs/superpowers/specs/2026-03-23-page-table-frame-free-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `crates/harmony-microkernel/src/vm/page_table.rs` | Change `unmap` signature |
| `crates/harmony-microkernel/src/vm/aarch64.rs` | Bottom-up prune + `is_table_empty` + tests |
| `crates/harmony-microkernel/src/vm/x86_64.rs` | Same prune logic + tests |
| `crates/harmony-microkernel/src/vm/mock.rs` | Accept and ignore callback + update tests |
| `crates/harmony-microkernel/src/vm/manager.rs` | Pass `buddy.free_frame` to unmap calls |

---

### Task 1: Change trait signature + update mock

**Files:**
- Modify: `crates/harmony-microkernel/src/vm/page_table.rs`
- Modify: `crates/harmony-microkernel/src/vm/mock.rs`

These must change together — the trait and its simplest implementation. This gets the project compiling again before touching the hardware implementations.

- [ ] **Step 1: Change `unmap` signature in page_table.rs**

In `crates/harmony-microkernel/src/vm/page_table.rs`, change line 27 from:

```rust
    fn unmap(&mut self, vaddr: VirtAddr) -> Result<PhysAddr, VmError>;
```

To:

```rust
    /// Remove the mapping at `vaddr`, returning the physical address that was mapped.
    ///
    /// `frame_dealloc` is called for each intermediate page table frame that
    /// becomes empty after the leaf is removed. Mock implementations may ignore it.
    fn unmap(
        &mut self,
        vaddr: VirtAddr,
        frame_dealloc: &mut dyn FnMut(PhysAddr),
    ) -> Result<PhysAddr, VmError>;
```

- [ ] **Step 2: Update MockPageTable::unmap**

In `crates/harmony-microkernel/src/vm/mock.rs`, change the `unmap` method (line 62) to accept the new callback parameter:

```rust
    fn unmap(
        &mut self,
        vaddr: VirtAddr,
        _frame_dealloc: &mut dyn FnMut(PhysAddr),
    ) -> Result<PhysAddr, VmError> {
        if !vaddr.is_page_aligned() {
            return Err(VmError::Unaligned(vaddr.as_u64()));
        }
        self.mappings
            .remove(&vaddr)
            .map(|(paddr, _)| paddr)
            .ok_or(VmError::NotMapped(vaddr))
    }
```

- [ ] **Step 3: Update mock tests**

In the mock test module, update `unmap_returns_paddr` and `unmap_unmapped_returns_error` tests to pass a no-op callback:

```rust
    fn noop_dealloc() -> impl FnMut(PhysAddr) {
        |_| {}
    }
```

Change `pt.unmap(vaddr)` to `pt.unmap(vaddr, &mut noop_dealloc())` in every mock test that calls unmap.

- [ ] **Step 4: Update all callers in manager.rs**

In `crates/harmony-microkernel/src/vm/manager.rs`, there are 3 `unmap` call sites. Update each to pass a no-op callback for now (Task 3 will wire them to the buddy allocator):

Line ~209 (map rollback):
```rust
let _ = space.page_table.unmap(rollback_vaddr, &mut |_| {});
```

Line ~314 (unmap_region):
```rust
let _ = space.page_table.unmap(page_vaddr, &mut |_| {});
```

Line ~462 (destroy_space):
```rust
let _ = space.page_table.unmap(page_vaddr, &mut |_| {});
```

- [ ] **Step 5: Run tests**

Run: `cargo test --workspace`
Expected: all tests pass (no behavior change yet — just signature update)

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-microkernel/src/vm/page_table.rs crates/harmony-microkernel/src/vm/mock.rs crates/harmony-microkernel/src/vm/manager.rs
git commit -m "refactor(vm): add frame_dealloc callback to PageTable::unmap

Symmetric with frame_alloc on map. All callers pass no-op for now.
Mock implementation ignores the callback.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Implement bottom-up prune in aarch64 + x86_64

**Files:**
- Modify: `crates/harmony-microkernel/src/vm/aarch64.rs`
- Modify: `crates/harmony-microkernel/src/vm/x86_64.rs`

- [ ] **Step 1: Update aarch64 unmap signature and implement pruning**

In `crates/harmony-microkernel/src/vm/aarch64.rs`, replace the `unmap` method (lines 271-304) with:

```rust
    fn unmap(
        &mut self,
        vaddr: VirtAddr,
        frame_dealloc: &mut dyn FnMut(PhysAddr),
    ) -> Result<PhysAddr, VmError> {
        if !vaddr.is_page_aligned() {
            return Err(VmError::Unaligned(vaddr.as_u64()));
        }

        // Walk levels 3 → 1, recording intermediate table addresses for pruning.
        let mut table_paddr = self.root;
        let mut walk: [(PhysAddr, usize); 3] = [(PhysAddr(0), 0); 3];

        for (i, level) in (1..=3).rev().enumerate() {
            let table = self.table_mut(table_paddr);
            let idx = Self::index(vaddr, level);
            let entry = table[idx];

            if !Self::is_valid(entry) {
                return Err(VmError::NotMapped(vaddr));
            }
            walk[i] = (table_paddr, idx);
            table_paddr = PhysAddr(entry & ADDR_MASK);
        }

        // Level 0: clear the leaf descriptor.
        let leaf_table_paddr = table_paddr;
        let pt = self.table_mut(leaf_table_paddr);
        let idx = Self::index(vaddr, 0);
        let entry = pt[idx];

        if !Self::is_valid(entry) {
            return Err(VmError::NotMapped(vaddr));
        }

        let old_paddr = PhysAddr(entry & ADDR_MASK);
        pt[idx] = 0;

        // Bottom-up prune: check if each table is now empty.
        // walk was filled top-down: walk[0]=(root, idx→L1), walk[1]=(L1, idx→L2),
        // walk[2]=(L2, idx→leaf). Reverse so we process leaf→L2→L1→root direction.
        // Root is never freed (walk only contains entries for non-root levels).
        let mut child_paddr = leaf_table_paddr;
        for &(parent_paddr, parent_idx) in walk.iter().rev() {
            if parent_paddr.as_u64() == 0 {
                break;
            }
            let child_table = self.table_mut(child_paddr);
            if Self::is_table_empty(child_table) {
                frame_dealloc(child_paddr);
                let parent_table = self.table_mut(parent_paddr);
                parent_table[parent_idx] = 0;
            } else {
                break; // non-empty table; ancestors are also non-empty
            }
            child_paddr = parent_paddr;
        }

        Ok(old_paddr)
    }
```

Add the helper method to the `impl` block (after `is_valid`):

```rust
    /// Returns `true` if all 512 entries in the table are invalid.
    fn is_table_empty(table: &[u64; 512]) -> bool {
        table.iter().all(|&e| !Self::is_valid(e))
    }
```

- [ ] **Step 2: Add aarch64 prune tests**

In the test module of aarch64.rs, add a `TrackingAllocator` and tests:

```rust
    /// Allocator that tracks allocations and accepts frees.
    struct TrackingAllocator {
        next: u64,
        limit: u64,
        alloc_count: usize,
        freed: Vec<PhysAddr>,
    }

    impl TrackingAllocator {
        fn new(base: u64, count: usize) -> Self {
            Self {
                next: base,
                limit: base + (count as u64) * 4096,
                alloc_count: 0,
                freed: Vec::new(),
            }
        }

        fn alloc(&mut self) -> Option<PhysAddr> {
            if self.next >= self.limit {
                return None;
            }
            let addr = PhysAddr(self.next);
            self.next += 4096;
            unsafe { core::ptr::write_bytes(addr.as_u64() as *mut u8, 0, 4096) };
            self.alloc_count += 1;
            Some(addr)
        }

        fn dealloc(&mut self, frame: PhysAddr) {
            self.freed.push(frame);
        }
    }

    #[test]
    fn unmap_prunes_empty_intermediate() {
        let (_arena, arena_base) = test_arena();
        let aligned = (arena_base.as_u64() + 4095) & !4095;
        let root = PhysAddr(aligned);
        unsafe { core::ptr::write_bytes(root.as_u64() as *mut u8, 0, 4096) };
        let mut alloc = TrackingAllocator::new(aligned + 4096, ARENA_TABLES - 1);
        let mut pt = unsafe { Aarch64PageTable::new(root, identity_phys_to_virt) };

        let vaddr = VirtAddr(0x1000);
        let paddr = PhysAddr(0xBEEF_0000);
        pt.map(vaddr, paddr, PageFlags::READABLE, &mut || alloc.alloc()).unwrap();

        // 3 intermediate tables were allocated (L3→L2→L1→leaf)
        let intermediates_allocated = alloc.alloc_count;
        assert_eq!(intermediates_allocated, 3, "mapping one page needs 3 intermediate tables");

        // Unmap — all 3 intermediates should be freed
        let result = pt.unmap(vaddr, &mut |frame| alloc.dealloc(frame)).unwrap();
        assert_eq!(result, paddr);
        assert_eq!(alloc.freed.len(), 3, "all 3 intermediate tables should be freed");
    }

    #[test]
    fn unmap_preserves_sibling_intermediates() {
        let (_arena, arena_base) = test_arena();
        let aligned = (arena_base.as_u64() + 4095) & !4095;
        let root = PhysAddr(aligned);
        unsafe { core::ptr::write_bytes(root.as_u64() as *mut u8, 0, 4096) };
        let mut alloc = TrackingAllocator::new(aligned + 4096, ARENA_TABLES - 1);
        let mut pt = unsafe { Aarch64PageTable::new(root, identity_phys_to_virt) };

        // Map two pages in the same L0 table (adjacent addresses)
        let vaddr1 = VirtAddr(0x1000);
        let vaddr2 = VirtAddr(0x2000);
        pt.map(vaddr1, PhysAddr(0xA000_0000), PageFlags::READABLE, &mut || alloc.alloc()).unwrap();
        pt.map(vaddr2, PhysAddr(0xB000_0000), PageFlags::READABLE, &mut || alloc.alloc()).unwrap();

        // Unmap first — leaf table still has sibling, so NO intermediates freed
        pt.unmap(vaddr1, &mut |frame| alloc.dealloc(frame)).unwrap();
        assert_eq!(alloc.freed.len(), 0, "sibling keeps intermediate alive");

        // Unmap second — now leaf table is empty, all 3 intermediates freed
        pt.unmap(vaddr2, &mut |frame| alloc.dealloc(frame)).unwrap();
        assert_eq!(alloc.freed.len(), 3, "all intermediates freed after last sibling removed");
    }
```

- [ ] **Step 3: Update existing aarch64 unmap tests**

Update `map_then_unmap` and `unmap_unmapped_returns_not_mapped` tests to pass a no-op dealloc callback:

```rust
let unmapped = pt.unmap(vaddr, &mut |_| {}).unwrap();
```

```rust
assert_eq!(pt.unmap(vaddr, &mut |_| {}), Err(VmError::NotMapped(vaddr)));
```

Also update `unaligned_address_errors` test:

```rust
assert_eq!(pt.unmap(unaligned, &mut |_| {}), Err(VmError::Unaligned(0x1001)));
```

And any other test that calls `pt.unmap(...)`.

- [ ] **Step 4: Implement x86_64 prune (same logic)**

In `crates/harmony-microkernel/src/vm/x86_64.rs`, apply the same changes to the `unmap` method (lines 221-254). The logic is identical but uses `PTE_PRESENT` and `PTE_ADDR_MASK` instead of `is_valid` and `ADDR_MASK`:

```rust
    fn unmap(
        &mut self,
        vaddr: VirtAddr,
        frame_dealloc: &mut dyn FnMut(PhysAddr),
    ) -> Result<PhysAddr, VmError> {
        // Same structure as aarch64: walk top-down recording (parent, idx),
        // clear leaf, prune bottom-up via walk.iter().rev()
        // Use entry & PTE_PRESENT == 0 for invalid check
        // Use entry & PTE_ADDR_MASK for address extraction
        // Add is_table_empty helper using PTE_PRESENT
    }
```

Add `is_table_empty` helper:
```rust
    fn is_table_empty(table: &[u64; 512]) -> bool {
        table.iter().all(|&e| e & PTE_PRESENT == 0)
    }
```

- [ ] **Step 5: Add x86_64 prune tests**

Add equivalent `TrackingAllocator`, `unmap_prunes_empty_intermediate`, and `unmap_preserves_sibling_intermediates` tests to the x86_64 test module. Follow the same pattern as aarch64 tests.

- [ ] **Step 6: Update existing x86_64 unmap tests**

Update all existing x86_64 tests that call `pt.unmap(...)` to pass `&mut |_| {}`.

- [ ] **Step 7: Run tests**

Run: `cargo test --workspace`
Expected: all tests pass (existing + new prune tests)

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-microkernel/src/vm/aarch64.rs crates/harmony-microkernel/src/vm/x86_64.rs
git commit -m "feat(vm): bottom-up prune of empty intermediate tables on unmap

After clearing the leaf entry, walk back up and free any intermediate
table whose 512 entries are all invalid. Root table is never freed.
Both aarch64 and x86_64 implementations with prune tests.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Wire manager to free intermediate frames via buddy

**Files:**
- Modify: `crates/harmony-microkernel/src/vm/manager.rs`

- [ ] **Step 1: Update unmap calls to pass buddy.free_frame**

Replace the 3 no-op callbacks from Task 1 with actual buddy allocator frees.

Line ~209 (map rollback) — the rollback path already frees intermediate frames from the local `intermediate_frames` vec, so the callback can remain no-op here (intermediates are freed by the rollback code, not by the unmap pruning):
```rust
let _ = space.page_table.unmap(rollback_vaddr, &mut |_| {});
```

Line ~314 (unmap_region) — wire to buddy:
```rust
let _ = space.page_table.unmap(page_vaddr, &mut |frame| {
    let _ = self.buddy.free_frame(frame);
});
```

**Important:** Check if `self.buddy` is accessible in the unmap_region context. The manager owns the buddy allocator. Read the method signature to understand borrow constraints. If there's a borrow conflict (page_table is borrowed via space, buddy is on self), you may need to split the borrows. The existing rollback code at line ~211 already calls `buddy_public.free_frame()` within the map method — follow the same pattern.

Line ~462 (destroy_space) — same pattern:
```rust
let _ = space.page_table.unmap(page_vaddr, &mut |frame| {
    let _ = self.buddy.free_frame(frame);
});
```

- [ ] **Step 2: Remove the TODO comment**

Find the TODO at lines ~456-458:
```rust
// TODO(harmony-qv2): intermediate page table frames (PDP/PD/PT
// levels) are not freed by unmap — they need a dedicated
// PageTable::destroy() method to walk and reclaim.
```

Remove it — the fix is now implemented.

- [ ] **Step 3: Run tests**

Run: `cargo test --workspace`
Expected: all tests pass

- [ ] **Step 4: Commit**

```bash
git add crates/harmony-microkernel/src/vm/manager.rs
git commit -m "feat(vm): wire buddy.free_frame to unmap's frame_dealloc callback

unmap_region and destroy_space now free intermediate page table frames
via the buddy allocator. Removes the TODO about leaking intermediates.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Full verification

- [ ] **Step 1: Run full workspace tests**

Run: `cargo test --workspace`

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace`

- [ ] **Step 3: Run fmt**

Run: `cargo fmt --all -- --check`
