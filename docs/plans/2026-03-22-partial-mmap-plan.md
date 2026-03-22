# Partial munmap/mprotect Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add region-splitting to AddressSpaceManager so munmap/mprotect work on sub-ranges within a single region, enabling ELF segment splitting.

**Architecture:** New `unmap_partial(pid, vaddr, len)` and `protect_partial(pid, vaddr, len, flags)` on `AddressSpaceManager` split the containing region's `frames` vec and update the `BTreeMap`. Existing `unmap_region`/`protect_region` become wrappers. `Kernel` gets new partial methods with guardian integration. `KernelBackend` passes `len` through instead of ignoring it.

**Tech Stack:** Rust, `no_std` (`alloc` only), `BTreeMap<VirtAddr, Region>`, `BuddyAllocator`, `PageTable` trait

**Spec:** `docs/specs/2026-03-22-partial-mmap-design.md`

---

## File Structure

| File | Changes |
|------|---------|
| Modify: `crates/harmony-microkernel/src/vm/manager.rs` | Add `unmap_partial`, `protect_partial`. Refactor `unmap_region` and `protect_region` to delegate. Helper `find_containing_region`. 12 unit tests. |
| Modify: `crates/harmony-microkernel/src/kernel.rs` | Add `vm_unmap_partial`, `vm_protect_partial` with Lyll/Nakaiah guardian integration. Refactor existing methods. |
| Modify: `crates/harmony-os/src/linuxulator.rs` | Update `KernelBackend::vm_munmap` and `vm_mprotect` to pass `len`. 2 integration tests. |

---

### Task 1: AddressSpaceManager — unmap_partial + protect_partial + 12 tests

**Files:**
- Modify: `crates/harmony-microkernel/src/vm/manager.rs`

This is the core task — all the region-splitting logic lives here.

- [ ] **Step 1: Add find_containing_region helper**

A helper that finds the region containing a given `[vaddr, vaddr+len)` range and returns its base address. Add after `protect_region` (~line 322):

```rust
    /// Find the region that fully contains `[vaddr, vaddr+len)`.
    /// Returns the region's base virtual address, or NotMapped if
    /// no single region contains the entire range.
    fn find_containing_region(
        &self,
        pid: u32,
        vaddr: VirtAddr,
        len: usize,
    ) -> Result<VirtAddr, VmError> {
        if len == 0 || vaddr.as_u64() % PAGE_SIZE != 0 || (len as u64) % PAGE_SIZE != 0 {
            return Err(VmError::Unaligned(vaddr.as_u64()));
        }
        let space = self.spaces.get(&pid).ok_or(VmError::NoSuchProcess(pid))?;
        let range_end = vaddr.as_u64() + len as u64;

        // Use range query: find regions whose base is <= vaddr.
        for (&base, region) in space.regions.range(..=vaddr).rev() {
            let region_end = base.as_u64() + region.len as u64;
            if base.as_u64() <= vaddr.as_u64() && range_end <= region_end {
                return Ok(base);
            }
            break; // Only need to check the one region that could contain vaddr
        }
        Err(VmError::NotMapped(vaddr))
    }
```

- [ ] **Step 2: Implement unmap_partial**

Add after `find_containing_region`:

```rust
    /// Unmap a sub-range within a single region.
    ///
    /// The range `[vaddr, vaddr+len)` must be fully contained within
    /// one existing region. Three cases:
    /// 1. Exact match → remove entire region
    /// 2. Prefix/suffix → shrink region
    /// 3. Middle → split into two regions (hole punch)
    pub fn unmap_partial(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        len: usize,
    ) -> Result<(), VmError> {
        let region_base = self.find_containing_region(pid, vaddr, len)?;

        let space = self.spaces.get_mut(&pid).unwrap();
        let region = space.regions.remove(&region_base).unwrap();

        let page_offset = ((vaddr.as_u64() - region_base.as_u64()) / PAGE_SIZE) as usize;
        let page_count = len / PAGE_SIZE as usize;
        let total_pages = region.len / PAGE_SIZE as usize;

        // Unmap the target pages from the page table.
        for i in 0..page_count {
            let page_vaddr = VirtAddr(vaddr.as_u64() + (i as u64) * PAGE_SIZE);
            let _ = space.page_table.unmap(page_vaddr);
        }

        // Partition frames: before | target | after
        let mut all_frames = region.frames;
        let after_frames = all_frames.split_off(page_offset + page_count);
        let target_frames = all_frames.split_off(page_offset);
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

        // Re-insert surviving region(s).
        let space = self.spaces.get_mut(&pid).unwrap();
        if !before_frames.is_empty() {
            space.regions.insert(
                region_base,
                Region {
                    len: before_frames.len() * PAGE_SIZE as usize,
                    flags: region.flags,
                    classification: region.classification,
                    frames: before_frames,
                },
            );
        }
        if !after_frames.is_empty() {
            let after_base = VirtAddr(vaddr.as_u64() + len as u64);
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

        Ok(())
    }
```

- [ ] **Step 3: Implement protect_partial**

Add after `unmap_partial`:

```rust
    /// Change permission flags on a sub-range within a single region.
    ///
    /// The range `[vaddr, vaddr+len)` must be fully contained within
    /// one existing region. Splits the region as needed so each piece
    /// has uniform flags.
    pub fn protect_partial(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        len: usize,
        new_flags: PageFlags,
    ) -> Result<(), VmError> {
        let region_base = self.find_containing_region(pid, vaddr, len)?;

        let space = self.spaces.get_mut(&pid).unwrap();
        let region = space.regions.remove(&region_base).unwrap();

        let page_offset = ((vaddr.as_u64() - region_base.as_u64()) / PAGE_SIZE) as usize;
        let page_count = len / PAGE_SIZE as usize;

        // Update page table entries for the target range.
        for i in 0..page_count {
            let page_vaddr = VirtAddr(vaddr.as_u64() + (i as u64) * PAGE_SIZE);
            space.page_table.set_flags(page_vaddr, new_flags)?;
        }

        // Partition frames: before | target | after
        let mut all_frames = region.frames;
        let after_frames = all_frames.split_off(page_offset + page_count);
        let target_frames = all_frames.split_off(page_offset);
        let before_frames = all_frames;

        // Re-insert up to 3 regions with appropriate flags.
        if !before_frames.is_empty() {
            space.regions.insert(
                region_base,
                Region {
                    len: before_frames.len() * PAGE_SIZE as usize,
                    flags: region.flags,
                    classification: region.classification,
                    frames: before_frames,
                },
            );
        }
        // Target region always exists (len > 0 validated by find_containing_region).
        space.regions.insert(
            vaddr,
            Region {
                len: target_frames.len() * PAGE_SIZE as usize,
                flags: new_flags,
                classification: region.classification,
                frames: target_frames,
            },
        );
        if !after_frames.is_empty() {
            let after_base = VirtAddr(vaddr.as_u64() + len as u64);
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

        Ok(())
    }
```

- [ ] **Step 4: Refactor unmap_region and protect_region as wrappers**

Replace `unmap_region` (~line 258):

```rust
    pub fn unmap_region(&mut self, pid: u32, vaddr: VirtAddr) -> Result<(), VmError> {
        let space = self.spaces.get(&pid).ok_or(VmError::NoSuchProcess(pid))?;
        let region = space.regions.get(&vaddr).ok_or(VmError::NotMapped(vaddr))?;
        let len = region.len;
        self.unmap_partial(pid, vaddr, len)
    }
```

Replace `protect_region` (~line 298):

```rust
    pub fn protect_region(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        new_flags: PageFlags,
    ) -> Result<(), VmError> {
        let space = self.spaces.get(&pid).ok_or(VmError::NoSuchProcess(pid))?;
        let region = space.regions.get(&vaddr).ok_or(VmError::NotMapped(vaddr))?;
        let len = region.len;
        self.protect_partial(pid, vaddr, len, new_flags)
    }
```

- [ ] **Step 5: Add 12 unit tests**

Add at end of `mod tests`:

```rust
    fn rx_user_flags() -> PageFlags {
        PageFlags::READABLE | PageFlags::EXECUTABLE | PageFlags::USER
    }

    // ── Partial unmap tests ──────────────────────────────────────

    #[test]
    fn test_unmap_partial_exact() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let vaddr = VirtAddr(0x1000);
        mgr.map_region(1, vaddr, PAGE_SIZE as usize * 4, rw_user_flags(), FrameClassification::empty()).unwrap();
        mgr.unmap_partial(1, vaddr, PAGE_SIZE as usize * 4).unwrap();
        assert!(mgr.space(1).unwrap().regions.is_empty());
    }

    #[test]
    fn test_unmap_partial_prefix() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let vaddr = VirtAddr(0x1000);
        mgr.map_region(1, vaddr, PAGE_SIZE as usize * 4, rw_user_flags(), FrameClassification::empty()).unwrap();
        // Remove first 2 pages
        mgr.unmap_partial(1, vaddr, PAGE_SIZE as usize * 2).unwrap();
        let regions = &mgr.space(1).unwrap().regions;
        assert_eq!(regions.len(), 1);
        let (&base, region) = regions.iter().next().unwrap();
        assert_eq!(base, VirtAddr(0x1000 + PAGE_SIZE * 2));
        assert_eq!(region.len, PAGE_SIZE as usize * 2);
        assert_eq!(region.frames.len(), 2);
    }

    #[test]
    fn test_unmap_partial_suffix() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let vaddr = VirtAddr(0x1000);
        mgr.map_region(1, vaddr, PAGE_SIZE as usize * 4, rw_user_flags(), FrameClassification::empty()).unwrap();
        // Remove last 2 pages
        let suffix_addr = VirtAddr(0x1000 + PAGE_SIZE * 2);
        mgr.unmap_partial(1, suffix_addr, PAGE_SIZE as usize * 2).unwrap();
        let regions = &mgr.space(1).unwrap().regions;
        assert_eq!(regions.len(), 1);
        let (&base, region) = regions.iter().next().unwrap();
        assert_eq!(base, vaddr);
        assert_eq!(region.len, PAGE_SIZE as usize * 2);
    }

    #[test]
    fn test_unmap_partial_middle() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let vaddr = VirtAddr(0x1000);
        mgr.map_region(1, vaddr, PAGE_SIZE as usize * 4, rw_user_flags(), FrameClassification::empty()).unwrap();
        // Punch hole in middle (page 1)
        let hole_addr = VirtAddr(0x1000 + PAGE_SIZE);
        mgr.unmap_partial(1, hole_addr, PAGE_SIZE as usize).unwrap();
        let regions = &mgr.space(1).unwrap().regions;
        assert_eq!(regions.len(), 2);
        // Before: 1 page at 0x1000
        let r1 = regions.get(&vaddr).unwrap();
        assert_eq!(r1.frames.len(), 1);
        // After: 2 pages at 0x1000 + 2*PAGE_SIZE
        let r2 = regions.get(&VirtAddr(0x1000 + PAGE_SIZE * 2)).unwrap();
        assert_eq!(r2.frames.len(), 2);
    }

    #[test]
    fn test_unmap_partial_not_contained() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let vaddr = VirtAddr(0x1000);
        mgr.map_region(1, vaddr, PAGE_SIZE as usize * 2, rw_user_flags(), FrameClassification::empty()).unwrap();
        // Try to unmap 3 pages starting at base (extends beyond region)
        let result = mgr.unmap_partial(1, vaddr, PAGE_SIZE as usize * 3);
        assert!(matches!(result, Err(VmError::NotMapped(_))));
    }

    #[test]
    fn test_unmap_partial_frees_frames() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let vaddr = VirtAddr(0x1000);
        mgr.map_region(1, vaddr, PAGE_SIZE as usize * 4, rw_user_flags(), FrameClassification::empty()).unwrap();
        let free_before = mgr.buddy_public().free_frame_count();
        // Free 2 of 4 pages
        mgr.unmap_partial(1, vaddr, PAGE_SIZE as usize * 2).unwrap();
        let free_after = mgr.buddy_public().free_frame_count();
        assert_eq!(free_after - free_before, 2);
    }

    #[test]
    fn test_unmap_partial_unaligned() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        // Unaligned vaddr
        let result = mgr.unmap_partial(1, VirtAddr(0x1001), PAGE_SIZE as usize);
        assert!(matches!(result, Err(VmError::Unaligned(_))));
        // Unaligned len
        let result = mgr.unmap_partial(1, VirtAddr(0x1000), 100);
        assert!(matches!(result, Err(VmError::Unaligned(_))));
        // Zero len
        let result = mgr.unmap_partial(1, VirtAddr(0x1000), 0);
        assert!(matches!(result, Err(VmError::Unaligned(_))));
    }

    // ── Partial protect tests ────────────────────────────────────

    #[test]
    fn test_protect_partial_exact() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let vaddr = VirtAddr(0x1000);
        mgr.map_region(1, vaddr, PAGE_SIZE as usize * 4, rw_user_flags(), FrameClassification::empty()).unwrap();
        mgr.protect_partial(1, vaddr, PAGE_SIZE as usize * 4, rx_user_flags()).unwrap();
        let regions = &mgr.space(1).unwrap().regions;
        assert_eq!(regions.len(), 1);
        assert_eq!(regions.get(&vaddr).unwrap().flags, rx_user_flags());
    }

    #[test]
    fn test_protect_partial_prefix() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let vaddr = VirtAddr(0x1000);
        mgr.map_region(1, vaddr, PAGE_SIZE as usize * 4, rw_user_flags(), FrameClassification::empty()).unwrap();
        // Change first 2 pages to RX
        mgr.protect_partial(1, vaddr, PAGE_SIZE as usize * 2, rx_user_flags()).unwrap();
        let regions = &mgr.space(1).unwrap().regions;
        assert_eq!(regions.len(), 2);
        assert_eq!(regions.get(&vaddr).unwrap().flags, rx_user_flags());
        assert_eq!(regions.get(&vaddr).unwrap().frames.len(), 2);
        let after_base = VirtAddr(0x1000 + PAGE_SIZE * 2);
        assert_eq!(regions.get(&after_base).unwrap().flags, rw_user_flags());
        assert_eq!(regions.get(&after_base).unwrap().frames.len(), 2);
    }

    #[test]
    fn test_protect_partial_suffix() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let vaddr = VirtAddr(0x1000);
        mgr.map_region(1, vaddr, PAGE_SIZE as usize * 4, rw_user_flags(), FrameClassification::empty()).unwrap();
        // Change last 2 pages to RX
        let suffix_addr = VirtAddr(0x1000 + PAGE_SIZE * 2);
        mgr.protect_partial(1, suffix_addr, PAGE_SIZE as usize * 2, rx_user_flags()).unwrap();
        let regions = &mgr.space(1).unwrap().regions;
        assert_eq!(regions.len(), 2);
        assert_eq!(regions.get(&vaddr).unwrap().flags, rw_user_flags());
        assert_eq!(regions.get(&suffix_addr).unwrap().flags, rx_user_flags());
    }

    #[test]
    fn test_protect_partial_middle() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let vaddr = VirtAddr(0x1000);
        mgr.map_region(1, vaddr, PAGE_SIZE as usize * 4, rw_user_flags(), FrameClassification::empty()).unwrap();
        // Change middle 2 pages to RX
        let mid_addr = VirtAddr(0x1000 + PAGE_SIZE);
        mgr.protect_partial(1, mid_addr, PAGE_SIZE as usize * 2, rx_user_flags()).unwrap();
        let regions = &mgr.space(1).unwrap().regions;
        assert_eq!(regions.len(), 3);
        assert_eq!(regions.get(&vaddr).unwrap().flags, rw_user_flags());
        assert_eq!(regions.get(&vaddr).unwrap().frames.len(), 1);
        assert_eq!(regions.get(&mid_addr).unwrap().flags, rx_user_flags());
        assert_eq!(regions.get(&mid_addr).unwrap().frames.len(), 2);
        let after_base = VirtAddr(0x1000 + PAGE_SIZE * 3);
        assert_eq!(regions.get(&after_base).unwrap().flags, rw_user_flags());
        assert_eq!(regions.get(&after_base).unwrap().frames.len(), 1);
    }

    #[test]
    fn test_protect_partial_not_contained() {
        let mut mgr = make_manager(16);
        mgr.create_space(1, default_budget(), mock_pt()).unwrap();
        let vaddr = VirtAddr(0x1000);
        mgr.map_region(1, vaddr, PAGE_SIZE as usize * 2, rw_user_flags(), FrameClassification::empty()).unwrap();
        let result = mgr.protect_partial(1, vaddr, PAGE_SIZE as usize * 3, rx_user_flags());
        assert!(matches!(result, Err(VmError::NotMapped(_))));
    }
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p harmony-microkernel 2>&1 | tail -15`
Expected: all tests pass including 12 new tests

- [ ] **Step 7: Run clippy and fmt**

Run: `cargo clippy -p harmony-microkernel -- -D warnings 2>&1 | tail -10`
Run: `cargo fmt --all -- --check`

- [ ] **Step 8: Commit**

```bash
git add crates/harmony-microkernel/src/vm/manager.rs
git commit -m "feat(vm): add unmap_partial and protect_partial for sub-range operations"
```

---

### Task 2: Kernel layer — vm_unmap_partial + vm_protect_partial with guardians

**Files:**
- Modify: `crates/harmony-microkernel/src/kernel.rs`

- [ ] **Step 1: Add vm_unmap_partial**

After `vm_unmap_region` (~line 731), add:

```rust
    /// Unmap a sub-range within a single region, with guardian integration.
    pub fn vm_unmap_partial(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        len: usize,
    ) -> Result<(), VmError> {
        // Identify which frames will be freed (before the unmap modifies state).
        let (target_frames, classification) = {
            let base = self.vm.find_containing_region(pid, vaddr, len)?;
            let space = self.vm.space(pid).unwrap();
            let region = space.regions.get(&base).unwrap();
            let page_offset = ((vaddr.as_u64() - base.as_u64()) / PAGE_SIZE) as usize;
            let page_count = len / PAGE_SIZE as usize;
            let frames: Vec<PhysAddr> = region.frames[page_offset..page_offset + page_count].to_vec();
            (frames, region.classification)
        };

        self.vm.unmap_partial(pid, vaddr, len)?;

        // Unregister freed frames from guardians.
        for &paddr in &target_frames {
            self.lyll.unregister_frame(paddr);
            if classification.contains(FrameClassification::ENCRYPTED) {
                self.nakaiah.unregister_frame(paddr);
            }
        }

        self.sync_guardian_state_hashes();
        Ok(())
    }
```

- [ ] **Step 2: Add vm_protect_partial**

After `vm_protect_region` (~line 757), add:

```rust
    /// Change permissions on a sub-range, with CidBacked→Snapshot promotion.
    pub fn vm_protect_partial(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        len: usize,
        new_flags: PageFlags,
    ) -> Result<(), VmError> {
        // Check writable transition before mutating.
        let was_writable = {
            let base = self.vm.find_containing_region(pid, vaddr, len)?;
            let space = self.vm.space(pid).unwrap();
            let region = space.regions.get(&base).unwrap();
            region.flags.contains(PageFlags::WRITABLE)
        };

        self.vm.protect_partial(pid, vaddr, len, new_flags)?;

        // Promote CidBacked → Snapshot for frames that just became writable.
        if !was_writable && new_flags.contains(PageFlags::WRITABLE) {
            let base = self.vm.find_containing_region(pid, vaddr, len)
                .unwrap_or(vaddr); // After protect, region may have split
            let space = self.vm.space(pid).unwrap();
            // Find the region that now starts at vaddr (the target range).
            if let Some(region) = space.regions.get(&vaddr) {
                for &paddr in &region.frames {
                    self.lyll.promote_to_snapshot(paddr);
                }
                self.sync_guardian_state_hashes();
            }
        }

        Ok(())
    }
```

- [ ] **Step 3: Refactor existing methods as wrappers**

Update `vm_unmap_region` (~line 731):

```rust
    pub fn vm_unmap_region(&mut self, pid: u32, vaddr: VirtAddr) -> Result<(), VmError> {
        let space = self.vm.space(pid).ok_or(VmError::NoSuchProcess(pid))?;
        let region = space.regions.get(&vaddr).ok_or(VmError::NotMapped(vaddr))?;
        let len = region.len;
        self.vm_unmap_partial(pid, vaddr, len)
    }
```

Update `vm_protect_region` (~line 757):

```rust
    pub fn vm_protect_region(
        &mut self,
        pid: u32,
        vaddr: VirtAddr,
        new_flags: PageFlags,
    ) -> Result<(), VmError> {
        let space = self.vm.space(pid).ok_or(VmError::NoSuchProcess(pid))?;
        let region = space.regions.get(&vaddr).ok_or(VmError::NotMapped(vaddr))?;
        let len = region.len;
        self.vm_protect_partial(pid, vaddr, len, new_flags)
    }
```

- [ ] **Step 4: Make find_containing_region public**

In `manager.rs`, change `find_containing_region` visibility from private to `pub` so the Kernel can call it:

```rust
    pub fn find_containing_region(
```

- [ ] **Step 5: Run tests**

Run: `cargo test -p harmony-microkernel 2>&1 | tail -15`
Expected: all existing kernel tests pass (the wrappers preserve behavior)

- [ ] **Step 6: Run clippy and fmt**

Run: `cargo clippy -p harmony-microkernel -- -D warnings`
Run: `cargo fmt --all -- --check`

- [ ] **Step 7: Commit**

```bash
git add crates/harmony-microkernel/src/vm/manager.rs crates/harmony-microkernel/src/kernel.rs
git commit -m "feat(kernel): add vm_unmap_partial and vm_protect_partial with guardian integration"
```

---

### Task 3: KernelBackend + Linuxulator integration tests

**Files:**
- Modify: `crates/harmony-os/src/linuxulator.rs`

- [ ] **Step 1: Update KernelBackend::vm_munmap**

In `KernelBackend` impl (~line 6568), replace the current `vm_munmap`:

```rust
        fn vm_munmap(&mut self, vaddr: u64, len: usize) -> Result<(), VmError> {
            use harmony_microkernel::vm::VirtAddr;
            self.kernel
                .vm_unmap_partial(self.pid, VirtAddr(vaddr), len)
        }
```

- [ ] **Step 2: Update KernelBackend::vm_mprotect**

In `KernelBackend` impl (~line 6577), replace the current `vm_mprotect`:

```rust
        fn vm_mprotect(
            &mut self,
            vaddr: u64,
            len: usize,
            flags: PageFlags,
        ) -> Result<(), VmError> {
            use harmony_microkernel::vm::VirtAddr;
            self.kernel
                .vm_protect_partial(self.pid, VirtAddr(vaddr), len, flags)
        }
```

- [ ] **Step 3: Add 2 integration tests**

Add at end of `mod tests` in linuxulator.rs:

```rust
    #[test]
    fn test_mprotect_sub_range() {
        let mock = VmMockBackend::new(1024);
        let mut lx = Linuxulator::with_arena(mock, 256 * 1024);

        // mmap 4 pages
        let addr = lx.dispatch_syscall(LinuxSyscall::Mmap {
            addr: 0,
            len: PAGE_SIZE as u64 * 4,
            prot: 3, // PROT_READ | PROT_WRITE
            flags: 0x22, // MAP_PRIVATE | MAP_ANONYMOUS
            fd: -1,
            offset: 0,
        });
        assert!(addr > 0);

        // mprotect middle 2 pages to PROT_READ
        let r = lx.dispatch_syscall(LinuxSyscall::Mprotect {
            addr: addr as u64 + PAGE_SIZE as u64,
            len: PAGE_SIZE as u64 * 2,
            prot: 1, // PROT_READ
        });
        assert_eq!(r, 0);
    }

    #[test]
    fn test_munmap_sub_range() {
        let mock = VmMockBackend::new(1024);
        let mut lx = Linuxulator::with_arena(mock, 256 * 1024);

        // mmap 4 pages
        let addr = lx.dispatch_syscall(LinuxSyscall::Mmap {
            addr: 0,
            len: PAGE_SIZE as u64 * 4,
            prot: 3,
            flags: 0x22,
            fd: -1,
            offset: 0,
        });
        assert!(addr > 0);

        // munmap middle 2 pages
        let r = lx.dispatch_syscall(LinuxSyscall::Munmap {
            addr: addr as u64 + PAGE_SIZE as u64,
            len: PAGE_SIZE as u64 * 2,
        });
        assert_eq!(r, 0);
    }
```

Note: These tests use `VmMockBackend` which always succeeds — they verify the syscall layer passes the right parameters. The real splitting is tested at the manager level.

- [ ] **Step 4: Run full workspace tests**

Run: `cargo test --workspace 2>&1 | tail -10`
Expected: all pass

- [ ] **Step 5: Run clippy and fmt**

Run: `cargo clippy --workspace -- -D warnings`
Run: `cargo fmt --all -- --check`

- [ ] **Step 6: Commit**

```bash
git add crates/harmony-os/src/linuxulator.rs
git commit -m "feat(linuxulator): wire KernelBackend to partial munmap/mprotect, add integration tests"
```
