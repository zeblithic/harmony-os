# Cross-Region munmap/mprotect Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `unmap_partial` and `protect_partial` in AddressSpaceManager to handle ranges spanning multiple regions, matching Linux munmap/mprotect semantics.

**Architecture:** Replace the single-region `find_containing_region` approach with an overlapping-region iterator. Each overlapping region is processed independently (split/remove/update). Gaps between regions are silently skipped. Kernel wrappers updated for per-region guardian checks.

**Tech Stack:** Rust (no_std + alloc), harmony-microkernel crate

**Spec:** `docs/specs/2026-03-23-cross-region-munmap-mprotect-design.md`

---

### File Structure

| File | Responsibility |
|------|---------------|
| `crates/harmony-microkernel/src/vm/manager.rs` | `unmap_partial`, `protect_partial`, overlapping-region helper, all tests |
| `crates/harmony-microkernel/src/kernel.rs` | `vm_unmap_partial`, `vm_protect_partial` kernel wrappers with guardian checks |

---

### Task 1: Add `find_overlapping_regions` helper

**Files:**
- Modify: `crates/harmony-microkernel/src/vm/manager.rs`

Add a `pub(crate)` helper that returns the base addresses of all regions overlapping a target range. This will be used by both `unmap_partial`, `protect_partial`, and the kernel wrappers.

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn find_overlapping_regions_basic() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        // Map three regions: [0x1000..0x3000), [0x5000..0x7000), [0x9000..0xB000)
        mgr.map_region(1, VirtAddr(0x1000), PAGE_SIZE as usize * 2, rw_user_flags(), FrameClassification::empty()).unwrap();
        mgr.map_region(1, VirtAddr(0x5000), PAGE_SIZE as usize * 2, rw_user_flags(), FrameClassification::empty()).unwrap();
        mgr.map_region(1, VirtAddr(0x9000), PAGE_SIZE as usize * 2, rw_user_flags(), FrameClassification::empty()).unwrap();

        // Range [0x2000..0xA000) should overlap all three regions.
        let overlaps = mgr.find_overlapping_regions(1, VirtAddr(0x2000), 0x8000).unwrap();
        assert_eq!(overlaps.len(), 3);
        assert_eq!(overlaps[0], VirtAddr(0x1000));
        assert_eq!(overlaps[1], VirtAddr(0x5000));
        assert_eq!(overlaps[2], VirtAddr(0x9000));

        // Range [0x3000..0x5000) overlaps nothing (gap).
        let overlaps = mgr.find_overlapping_regions(1, VirtAddr(0x3000), 0x2000).unwrap();
        assert_eq!(overlaps.len(), 0);

        // Range [0x6000..0x6000+PAGE_SIZE) overlaps only [0x5000..0x7000).
        let overlaps = mgr.find_overlapping_regions(1, VirtAddr(0x6000), PAGE_SIZE as usize).unwrap();
        assert_eq!(overlaps.len(), 1);
        assert_eq!(overlaps[0], VirtAddr(0x5000));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p harmony-microkernel find_overlapping_regions_basic 2>&1 | tail -5`
Expected: FAIL — method does not exist

- [ ] **Step 3: Implement `find_overlapping_regions`**

Add after `find_containing_region` (around line 297):

```rust
    /// Find all regions that overlap `[vaddr, vaddr+len)`.
    ///
    /// Returns a Vec of base addresses (sorted ascending) for every region
    /// whose range intersects the target. Returns an empty Vec if no regions
    /// overlap (gaps are silently skipped). Returns `Err` for invalid
    /// arguments (zero len, unaligned) or missing process.
    pub(crate) fn find_overlapping_regions(
        &self,
        pid: u32,
        vaddr: VirtAddr,
        len: usize,
    ) -> Result<Vec<VirtAddr>, VmError> {
        if len == 0 || vaddr.as_u64() % PAGE_SIZE != 0 || (len as u64) % PAGE_SIZE != 0 {
            return Err(VmError::Unaligned(vaddr.as_u64()));
        }
        let space = self.spaces.get(&pid).ok_or(VmError::NoSuchProcess(pid))?;
        let range_end = vaddr.as_u64() + len as u64;
        let mut result = Vec::new();

        // Scan regions that could overlap: any region whose base < range_end.
        // We start from the first region whose base could overlap (i.e.,
        // base + region.len > vaddr.as_u64()). The BTreeMap is sorted by
        // base, so we can iterate forward.
        for (&base, region) in space.regions.iter() {
            let region_end = base.as_u64() + region.len as u64;
            if region_end <= vaddr.as_u64() {
                continue; // region is entirely before target
            }
            if base.as_u64() >= range_end {
                break; // region is entirely after target (and all subsequent)
            }
            // Region overlaps the target range.
            result.push(base);
        }
        Ok(result)
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p harmony-microkernel find_overlapping_regions_basic 2>&1 | tail -5`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/vm/manager.rs
git commit -m "feat(vm): add find_overlapping_regions helper

Returns sorted base addresses of all regions overlapping a target
range. Foundation for cross-region munmap/mprotect."
```

---

### Task 2: Rewrite `unmap_partial` for cross-region support

**Files:**
- Modify: `crates/harmony-microkernel/src/vm/manager.rs`

Replace the current `unmap_partial` (which calls `find_containing_region` and handles one region) with a version that iterates all overlapping regions.

- [ ] **Step 1: Write failing tests**

Add these tests at the end of the test module:

```rust
    #[test]
    fn unmap_spanning_two_regions() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        // Two adjacent 2-page regions: [0x1000..0x3000), [0x3000..0x5000)
        mgr.map_region(1, VirtAddr(0x1000), PAGE_SIZE as usize * 2, rw_user_flags(), FrameClassification::empty()).unwrap();
        mgr.map_region(1, VirtAddr(0x3000), PAGE_SIZE as usize * 2, rw_user_flags(), FrameClassification::empty()).unwrap();
        let initial_free = mgr.buddy_public().free_frame_count();

        // Unmap [0x2000..0x4000) — spans both regions.
        mgr.unmap_partial(1, VirtAddr(0x2000), PAGE_SIZE as usize * 2).unwrap();

        assert_eq!(mgr.buddy_public().free_frame_count(), initial_free + 2);
        let regions = &mgr.space(1).unwrap().regions;
        // Should have: [0x1000..0x2000) and [0x4000..0x5000)
        assert_eq!(regions.len(), 2);
        assert_eq!(regions.get(&VirtAddr(0x1000)).unwrap().len, PAGE_SIZE as usize);
        assert_eq!(regions.get(&VirtAddr(0x4000)).unwrap().len, PAGE_SIZE as usize);
    }

    #[test]
    fn unmap_covering_middle_region() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        // Three regions: [0x1000..0x3000), [0x3000..0x5000), [0x5000..0x7000)
        mgr.map_region(1, VirtAddr(0x1000), PAGE_SIZE as usize * 2, rw_user_flags(), FrameClassification::empty()).unwrap();
        mgr.map_region(1, VirtAddr(0x3000), PAGE_SIZE as usize * 2, rw_user_flags(), FrameClassification::empty()).unwrap();
        mgr.map_region(1, VirtAddr(0x5000), PAGE_SIZE as usize * 2, rw_user_flags(), FrameClassification::empty()).unwrap();
        let initial_free = mgr.buddy_public().free_frame_count();

        // Unmap [0x2000..0x6000) — partial first, all of middle, partial last.
        mgr.unmap_partial(1, VirtAddr(0x2000), PAGE_SIZE as usize * 4).unwrap();

        assert_eq!(mgr.buddy_public().free_frame_count(), initial_free + 4);
        let regions = &mgr.space(1).unwrap().regions;
        assert_eq!(regions.len(), 2);
        assert_eq!(regions.get(&VirtAddr(0x1000)).unwrap().len, PAGE_SIZE as usize);
        assert_eq!(regions.get(&VirtAddr(0x6000)).unwrap().len, PAGE_SIZE as usize);
    }

    #[test]
    fn unmap_with_gap() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        // Two regions with gap: [0x1000..0x2000), [0x4000..0x5000)
        mgr.map_region(1, VirtAddr(0x1000), PAGE_SIZE as usize, rw_user_flags(), FrameClassification::empty()).unwrap();
        mgr.map_region(1, VirtAddr(0x4000), PAGE_SIZE as usize, rw_user_flags(), FrameClassification::empty()).unwrap();
        let initial_free = mgr.buddy_public().free_frame_count();

        // Unmap [0x1000..0x5000) — includes gap [0x2000..0x4000).
        mgr.unmap_partial(1, VirtAddr(0x1000), PAGE_SIZE as usize * 4).unwrap();

        assert_eq!(mgr.buddy_public().free_frame_count(), initial_free + 2);
        let regions = &mgr.space(1).unwrap().regions;
        assert_eq!(regions.len(), 0);
    }

    #[test]
    fn unmap_entire_two_regions() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        mgr.map_region(1, VirtAddr(0x1000), PAGE_SIZE as usize * 2, rw_user_flags(), FrameClassification::empty()).unwrap();
        mgr.map_region(1, VirtAddr(0x3000), PAGE_SIZE as usize * 2, rw_user_flags(), FrameClassification::empty()).unwrap();
        let initial_free = mgr.buddy_public().free_frame_count();

        // Unmap exactly both regions: [0x1000..0x5000).
        mgr.unmap_partial(1, VirtAddr(0x1000), PAGE_SIZE as usize * 4).unwrap();

        assert_eq!(mgr.buddy_public().free_frame_count(), initial_free + 4);
        assert_eq!(mgr.space(1).unwrap().regions.len(), 0);
    }

    #[test]
    fn unmap_no_overlap() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        mgr.map_region(1, VirtAddr(0x1000), PAGE_SIZE as usize, rw_user_flags(), FrameClassification::empty()).unwrap();

        // Unmap a range that doesn't overlap any region.
        let result = mgr.unmap_partial(1, VirtAddr(0x5000), PAGE_SIZE as usize);
        assert!(result.is_ok(), "unmapping non-overlapping range should succeed (Linux semantics)");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel unmap_spanning 2>&1 | tail -5`
Expected: FAIL — current implementation requires single containing region

- [ ] **Step 3: Rewrite `unmap_partial`**

Replace the current `unmap_partial` method (lines 304-381) with:

```rust
    /// Unmap a range `[vaddr, vaddr+len)` that may span multiple regions.
    ///
    /// Each overlapping region is processed independently: the overlap is
    /// removed and surviving portions (before/after) are re-inserted.
    /// Gaps (unmapped pages) in the target range are silently skipped,
    /// matching Linux munmap semantics.
    pub fn unmap_partial(&mut self, pid: u32, vaddr: VirtAddr, len: usize) -> Result<(), VmError> {
        let bases = self.find_overlapping_regions(pid, vaddr, len)?;
        if bases.is_empty() {
            return Ok(()); // nothing to unmap
        }

        let range_end = vaddr.as_u64() + len as u64;

        for base in bases {
            let region = {
                let space = self.spaces.get_mut(&pid).unwrap();
                space.regions.remove(&base).unwrap()
            };
            let region_end = base.as_u64() + region.len as u64;

            // Compute overlap within this region.
            let overlap_start = vaddr.as_u64().max(base.as_u64());
            let overlap_end = range_end.min(region_end);
            let overlap_page_offset =
                ((overlap_start - base.as_u64()) / PAGE_SIZE) as usize;
            let overlap_page_count =
                ((overlap_end - overlap_start) / PAGE_SIZE) as usize;

            // Unmap target pages from page table.
            {
                let Self {
                    spaces,
                    buddy_public,
                    ..
                } = self;
                let space = spaces.get_mut(&pid).unwrap();
                for i in 0..overlap_page_count {
                    let page_vaddr =
                        VirtAddr(overlap_start + (i as u64) * PAGE_SIZE);
                    let _ = space.page_table.unmap(page_vaddr, &mut |frame| {
                        let _ = buddy_public.free_frame(frame);
                    });
                }
            }

            // Partition frames: before | overlap | after
            let mut all_frames = region.frames;
            let after_frames =
                all_frames.split_off(overlap_page_offset + overlap_page_count);
            let target_frames = all_frames.split_off(overlap_page_offset);
            let before_frames = all_frames;

            // Free target frames.
            let use_kernel = region
                .classification
                .contains(FrameClassification::ENCRYPTED)
                && self.buddy_kernel.total_frame_count() > 0;
            let buddy = if use_kernel {
                &mut self.buddy_kernel
            } else {
                &mut self.buddy_public
            };
            for &paddr in &target_frames {
                let _ = self.cap_tracker.remove_mapping(paddr, pid);
                let _ = buddy.free_frame(paddr);
            }

            // Re-insert surviving regions.
            let space = self.spaces.get_mut(&pid).unwrap();
            if !before_frames.is_empty() {
                space.regions.insert(
                    base,
                    Region {
                        len: before_frames.len() * PAGE_SIZE as usize,
                        flags: region.flags,
                        classification: region.classification,
                        frames: before_frames,
                    },
                );
            }
            if !after_frames.is_empty() {
                let after_base = VirtAddr(overlap_end);
                space.regions.insert(
                    after_base,
                    Region {
                        len: after_frames.len() * PAGE_SIZE as usize,
                        flags: region.flags,
                        classification: region.classification,
                        frames: after_frames,
                    },
                );
            }
        }
        Ok(())
    }
```

- [ ] **Step 4: Run all tests**

Run: `cargo test -p harmony-microkernel 2>&1 | tail -5`
Expected: all tests pass (both new cross-region and existing single-region tests)

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/vm/manager.rs
git commit -m "feat(vm): rewrite unmap_partial for cross-region support

Iterate overlapping regions instead of requiring a single containing
region. Gaps silently skipped. Existing single-region tests pass."
```

---

### Task 3: Rewrite `protect_partial` for cross-region support

**Files:**
- Modify: `crates/harmony-microkernel/src/vm/manager.rs`

- [ ] **Step 1: Write failing tests**

```rust
    #[test]
    fn protect_spanning_two_regions() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        // Two adjacent 2-page regions: [0x1000..0x3000), [0x3000..0x5000)
        mgr.map_region(1, VirtAddr(0x1000), PAGE_SIZE as usize * 2, rw_user_flags(), FrameClassification::empty()).unwrap();
        mgr.map_region(1, VirtAddr(0x3000), PAGE_SIZE as usize * 2, rw_user_flags(), FrameClassification::empty()).unwrap();

        // Protect [0x2000..0x4000) as RX.
        mgr.protect_partial(1, VirtAddr(0x2000), PAGE_SIZE as usize * 2, rx_user_flags()).unwrap();

        let regions = &mgr.space(1).unwrap().regions;
        // Should have 4 regions: [0x1000..0x2000) RW, [0x2000..0x3000) RX,
        //                        [0x3000..0x4000) RX, [0x4000..0x5000) RW
        // Actually, the two RX regions could be separate (from different original regions).
        assert_eq!(regions.len(), 4);
        assert_eq!(regions.get(&VirtAddr(0x1000)).unwrap().flags, rw_user_flags());
        assert_eq!(regions.get(&VirtAddr(0x2000)).unwrap().flags, rx_user_flags());
        assert_eq!(regions.get(&VirtAddr(0x3000)).unwrap().flags, rx_user_flags());
        assert_eq!(regions.get(&VirtAddr(0x4000)).unwrap().flags, rw_user_flags());
    }

    #[test]
    fn protect_with_gap() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        // Two regions with gap: [0x1000..0x2000), [0x4000..0x5000)
        mgr.map_region(1, VirtAddr(0x1000), PAGE_SIZE as usize, rw_user_flags(), FrameClassification::empty()).unwrap();
        mgr.map_region(1, VirtAddr(0x4000), PAGE_SIZE as usize, rw_user_flags(), FrameClassification::empty()).unwrap();

        // Protect [0x1000..0x5000) — includes gap.
        mgr.protect_partial(1, VirtAddr(0x1000), PAGE_SIZE as usize * 4, rx_user_flags()).unwrap();

        let regions = &mgr.space(1).unwrap().regions;
        assert_eq!(regions.len(), 2);
        assert_eq!(regions.get(&VirtAddr(0x1000)).unwrap().flags, rx_user_flags());
        assert_eq!(regions.get(&VirtAddr(0x4000)).unwrap().flags, rx_user_flags());
    }

    #[test]
    fn protect_spanning_three_regions() {
        let mut mgr = make_manager(32);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        // Three adjacent 2-page regions.
        mgr.map_region(1, VirtAddr(0x1000), PAGE_SIZE as usize * 2, rw_user_flags(), FrameClassification::empty()).unwrap();
        mgr.map_region(1, VirtAddr(0x3000), PAGE_SIZE as usize * 2, rw_user_flags(), FrameClassification::empty()).unwrap();
        mgr.map_region(1, VirtAddr(0x5000), PAGE_SIZE as usize * 2, rw_user_flags(), FrameClassification::empty()).unwrap();

        // Protect [0x2000..0x6000) — partial first, all of middle, partial last.
        mgr.protect_partial(1, VirtAddr(0x2000), PAGE_SIZE as usize * 4, rx_user_flags()).unwrap();

        let regions = &mgr.space(1).unwrap().regions;
        // [0x1000..0x2000) RW, [0x2000..0x3000) RX, [0x3000..0x5000) RX,
        // [0x5000..0x6000) RX, [0x6000..0x7000) RW
        assert_eq!(regions.len(), 5);
        assert_eq!(regions.get(&VirtAddr(0x1000)).unwrap().flags, rw_user_flags());
        assert_eq!(regions.get(&VirtAddr(0x6000)).unwrap().flags, rw_user_flags());
        // Middle regions should be RX.
        assert_eq!(regions.get(&VirtAddr(0x2000)).unwrap().flags, rx_user_flags());
        assert_eq!(regions.get(&VirtAddr(0x3000)).unwrap().flags, rx_user_flags());
        assert_eq!(regions.get(&VirtAddr(0x5000)).unwrap().flags, rx_user_flags());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p harmony-microkernel protect_spanning 2>&1 | tail -5`
Expected: FAIL

- [ ] **Step 3: Rewrite `protect_partial`**

Replace the current `protect_partial` method (lines 388-455) with:

```rust
    /// Change permission flags on `[vaddr, vaddr+len)`, spanning multiple regions.
    ///
    /// Each overlapping region is split into up to three parts: before
    /// (unchanged), overlap (new flags), after (unchanged). Gaps in the
    /// target range are silently skipped.
    pub fn protect_partial(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        len: usize,
        new_flags: PageFlags,
    ) -> Result<(), VmError> {
        let bases = self.find_overlapping_regions(pid, vaddr, len)?;
        if bases.is_empty() {
            return Ok(());
        }

        let range_end = vaddr.as_u64() + len as u64;

        for base in bases {
            let region_len = {
                let space = self.spaces.get(&pid).unwrap();
                space.regions.get(&base).unwrap().len
            };
            let region_end = base.as_u64() + region_len as u64;

            let overlap_start = vaddr.as_u64().max(base.as_u64());
            let overlap_end = range_end.min(region_end);
            let overlap_page_count =
                ((overlap_end - overlap_start) / PAGE_SIZE) as usize;

            // Update page table flags BEFORE modifying region map.
            {
                let space = self.spaces.get_mut(&pid).unwrap();
                for i in 0..overlap_page_count {
                    let page_vaddr =
                        VirtAddr(overlap_start + (i as u64) * PAGE_SIZE);
                    space.page_table.set_flags(page_vaddr, new_flags)?;
                }
            }

            // Remove region, partition, re-insert.
            let space = self.spaces.get_mut(&pid).unwrap();
            let region = space.regions.remove(&base).unwrap();
            let overlap_page_offset =
                ((overlap_start - base.as_u64()) / PAGE_SIZE) as usize;

            let mut all_frames = region.frames;
            let after_frames =
                all_frames.split_off(overlap_page_offset + overlap_page_count);
            let target_frames = all_frames.split_off(overlap_page_offset);
            let before_frames = all_frames;

            if !before_frames.is_empty() {
                space.regions.insert(
                    base,
                    Region {
                        len: before_frames.len() * PAGE_SIZE as usize,
                        flags: region.flags,
                        classification: region.classification,
                        frames: before_frames,
                    },
                );
            }
            space.regions.insert(
                VirtAddr(overlap_start),
                Region {
                    len: target_frames.len() * PAGE_SIZE as usize,
                    flags: new_flags,
                    classification: region.classification,
                    frames: target_frames,
                },
            );
            if !after_frames.is_empty() {
                space.regions.insert(
                    VirtAddr(overlap_end),
                    Region {
                        len: after_frames.len() * PAGE_SIZE as usize,
                        flags: region.flags,
                        classification: region.classification,
                        frames: after_frames,
                    },
                );
            }
        }
        Ok(())
    }
```

- [ ] **Step 4: Run all tests**

Run: `cargo test -p harmony-microkernel 2>&1 | tail -5`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/vm/manager.rs
git commit -m "feat(vm): rewrite protect_partial for cross-region support

Iterate overlapping regions, split each independently. Page table
flags updated before region map mutation. Gaps silently skipped."
```

---

### Task 4: Update kernel wrappers for cross-region guardian checks

**Files:**
- Modify: `crates/harmony-microkernel/src/kernel.rs`

Update `vm_unmap_partial` and `vm_protect_partial` to iterate overlapping regions for per-region guardian checks instead of using `find_containing_region`.

- [ ] **Step 1: Rewrite `vm_unmap_partial`**

Replace the current implementation (lines 739-769) with:

```rust
    pub fn vm_unmap_partial(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        len: usize,
    ) -> Result<(), VmError> {
        // Collect frames to unregister from guardians BEFORE the unmap
        // modifies region state. Each overlapping region may have different
        // classification.
        let bases = self.vm.find_overlapping_regions(pid, vaddr, len)?;
        let range_end = vaddr.as_u64() + len as u64;

        let mut frames_to_unregister: Vec<(PhysAddr, FrameClassification)> = Vec::new();
        for &base in &bases {
            let space = self.vm.space(pid).unwrap();
            let region = space.regions.get(&base).unwrap();
            let region_end = base.as_u64() + region.len as u64;
            let overlap_start = vaddr.as_u64().max(base.as_u64());
            let overlap_end = range_end.min(region_end);
            let page_offset = ((overlap_start - base.as_u64()) / PAGE_SIZE) as usize;
            let page_count = ((overlap_end - overlap_start) / PAGE_SIZE) as usize;
            for &paddr in &region.frames[page_offset..page_offset + page_count] {
                frames_to_unregister.push((paddr, region.classification));
            }
        }

        self.vm.unmap_partial(pid, vaddr, len)?;

        // Unregister freed frames from guardians.
        for (paddr, classification) in frames_to_unregister {
            self.lyll.unregister_frame(paddr);
            if classification.contains(FrameClassification::ENCRYPTED) {
                self.nakaiah.unregister_frame(paddr);
            }
        }

        if !bases.is_empty() {
            self.sync_guardian_state_hashes();
        }
        Ok(())
    }
```

- [ ] **Step 2: Rewrite `vm_protect_partial`**

Replace the current implementation (lines 788-820) with:

```rust
    pub fn vm_protect_partial(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        len: usize,
        new_flags: PageFlags,
    ) -> Result<(), VmError> {
        // Check per-region writability BEFORE mutating.
        let bases = self.vm.find_overlapping_regions(pid, vaddr, len)?;
        let range_end = vaddr.as_u64() + len as u64;

        // Collect frames that need Snapshot promotion (from regions that
        // were NOT previously writable, now becoming writable).
        let mut frames_to_promote: Vec<PhysAddr> = Vec::new();
        if new_flags.contains(PageFlags::WRITABLE) {
            for &base in &bases {
                let space = self.vm.space(pid).unwrap();
                let region = space.regions.get(&base).unwrap();
                if !region.flags.contains(PageFlags::WRITABLE) {
                    let region_end = base.as_u64() + region.len as u64;
                    let overlap_start = vaddr.as_u64().max(base.as_u64());
                    let overlap_end = range_end.min(region_end);
                    let page_offset =
                        ((overlap_start - base.as_u64()) / PAGE_SIZE) as usize;
                    let page_count =
                        ((overlap_end - overlap_start) / PAGE_SIZE) as usize;
                    for &paddr in &region.frames[page_offset..page_offset + page_count] {
                        frames_to_promote.push(paddr);
                    }
                }
            }
        }

        self.vm.protect_partial(pid, vaddr, len, new_flags)?;

        // Promote CidBacked → Snapshot for frames that just became writable.
        for paddr in &frames_to_promote {
            self.lyll.promote_to_snapshot(*paddr);
        }
        if !frames_to_promote.is_empty() {
            self.sync_guardian_state_hashes();
        }

        Ok(())
    }
```

- [ ] **Step 3: Run all tests**

Run: `cargo test --workspace 2>&1 | tail -10`
Expected: all tests pass across all crates

- [ ] **Step 4: Run clippy**

Run: `cargo clippy --workspace 2>&1 | tail -10`
Expected: no new warnings

- [ ] **Step 5: Commit**

```bash
git add crates/harmony-microkernel/src/kernel.rs
git commit -m "feat(kernel): update vm wrappers for cross-region guardian checks

vm_unmap_partial: iterate overlapping regions for per-region
classification-based guardian unregistration.
vm_protect_partial: per-region writability check for Snapshot promotion."
```

---

### Task 5: Final verification

**Files:**
- No changes expected (fix any issues found)

- [ ] **Step 1: Run full workspace tests**

Run: `cargo test --workspace 2>&1 | tail -10`
Expected: all tests pass

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace 2>&1 | tail -10`
Expected: no warnings

- [ ] **Step 3: Run fmt**

Run: `cargo fmt --all -- --check 2>&1 | tail -5`
Expected: clean

- [ ] **Step 4: Commit any fixes**

```bash
git add -A
git commit -m "style: format and clippy fixes for cross-region ops"
```
(Skip if no fixes needed.)
