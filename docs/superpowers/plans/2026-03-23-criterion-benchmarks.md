# Criterion Benchmarks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish Criterion benchmark framework and baseline measurements for 5 core Ring 2 microkernel operations.

**Architecture:** Add criterion as workspace dependency, create 5 bench files in `crates/harmony-microkernel/benches/` with `harness = false` targets. Each bench uses existing test setup patterns (BuddyAllocator::new, MockPageTable::new, FidTracker::new, EchoServer::new, CapTracker::new).

**Tech Stack:** Rust, Criterion 0.5, harmony-microkernel

**Spec:** `docs/superpowers/specs/2026-03-23-criterion-benchmarks-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `Cargo.toml` (workspace root) | Add criterion to workspace dependencies |
| `crates/harmony-microkernel/Cargo.toml` | Add criterion dev-dep + 5 `[[bench]]` targets |
| `crates/harmony-microkernel/benches/buddy_alloc.rs` | Buddy allocator benchmarks |
| `crates/harmony-microkernel/benches/page_table.rs` | MockPageTable benchmarks |
| `crates/harmony-microkernel/benches/fid_tracker.rs` | FidTracker benchmarks |
| `crates/harmony-microkernel/benches/ipc_echo.rs` | EchoServer IPC benchmarks |
| `crates/harmony-microkernel/benches/cap_tracker.rs` | CapTracker benchmarks |

---

### Task 1: Criterion framework setup + buddy_alloc benchmark

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `crates/harmony-microkernel/Cargo.toml`
- Create: `crates/harmony-microkernel/benches/buddy_alloc.rs`

This task establishes the framework and proves it works with the first benchmark.

- [ ] **Step 1: Add criterion to workspace dependencies**

In the root `Cargo.toml`, find `[workspace.dependencies]` and add:
```toml
criterion = { version = "0.5", features = ["html_reports"] }
```

- [ ] **Step 2: Add criterion dev-dep and bench targets to harmony-microkernel**

In `crates/harmony-microkernel/Cargo.toml`, add to `[dev-dependencies]`:
```toml
criterion = { workspace = true }
```

Add bench targets after `[dev-dependencies]`:
```toml
[[bench]]
name = "buddy_alloc"
harness = false

[[bench]]
name = "page_table"
harness = false

[[bench]]
name = "fid_tracker"
harness = false

[[bench]]
name = "ipc_echo"
harness = false

[[bench]]
name = "cap_tracker"
harness = false
```

- [ ] **Step 3: Create buddy_alloc.rs benchmark**

Create `crates/harmony-microkernel/benches/buddy_alloc.rs`:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use harmony_microkernel::vm::{PhysAddr, BuddyAllocator};

fn make_allocator(frame_count: usize) -> BuddyAllocator {
    BuddyAllocator::new(PhysAddr(0x10_0000), frame_count).unwrap()
}

fn bench_alloc_frame(c: &mut Criterion) {
    let mut group = c.benchmark_group("buddy/alloc_frame");
    group.bench_function("single", |b| {
        let mut alloc = make_allocator(1024);
        b.iter(|| {
            let addr = alloc.alloc_frame().unwrap();
            alloc.free_frame(addr).unwrap();
            black_box(addr);
        });
    });
    group.finish();
}

fn bench_alloc_free_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("buddy/alloc_free_cycle");
    group.bench_function("100_frames", |b| {
        let mut alloc = make_allocator(1024);
        b.iter(|| {
            let mut addrs = Vec::with_capacity(100);
            for _ in 0..100 {
                addrs.push(alloc.alloc_frame().unwrap());
            }
            for addr in addrs {
                alloc.free_frame(addr).unwrap();
            }
        });
    });
    group.finish();
}

fn bench_order_alloc(c: &mut Criterion) {
    let mut group = c.benchmark_group("buddy/order_alloc");
    for order in [0, 1, 2, 3, 4, 5] {
        group.bench_function(format!("order_{order}"), |b| {
            let mut alloc = make_allocator(1024);
            b.iter(|| {
                let addr = alloc.alloc(order).unwrap();
                alloc.free(addr, order).unwrap();
                black_box(addr);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_alloc_frame, bench_alloc_free_cycle, bench_order_alloc);
criterion_main!(benches);
```

**Important:** Check that `BuddyAllocator` is publicly accessible from the crate root. It might be at `harmony_microkernel::vm::BuddyAllocator` or `harmony_microkernel::vm::buddy::BuddyAllocator`. Read `crates/harmony-microkernel/src/vm/mod.rs` to find the re-export path. Adapt imports accordingly.

- [ ] **Step 4: Run the benchmark**

Run: `cargo bench -p harmony-microkernel --bench buddy_alloc`
Expected: Criterion output with timing numbers for buddy allocator operations

Also run: `cargo test --workspace` to verify nothing broke.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml crates/harmony-microkernel/Cargo.toml crates/harmony-microkernel/benches/buddy_alloc.rs
git commit -m "feat(bench): Criterion framework + buddy allocator benchmarks

Add criterion 0.5 as workspace dep. 5 bench targets declared.
First benchmark: buddy alloc_frame, alloc_free_cycle, order_alloc.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Page table benchmark

**Files:**
- Create: `crates/harmony-microkernel/benches/page_table.rs`

- [ ] **Step 1: Create page_table.rs**

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use harmony_microkernel::vm::{PageFlags, PhysAddr, VirtAddr};
use harmony_microkernel::vm::mock::MockPageTable;
use harmony_microkernel::vm::page_table::PageTable;

fn bench_map_single(c: &mut Criterion) {
    c.bench_function("page_table/map_single", |b| {
        let mut pt = MockPageTable::new(PhysAddr(0x10_0000));
        let mut next_vaddr = 0x1000u64;
        b.iter(|| {
            let vaddr = VirtAddr(next_vaddr);
            pt.map(vaddr, PhysAddr(0xDEAD_0000), PageFlags::READABLE | PageFlags::WRITABLE, &mut || None).unwrap();
            next_vaddr += 4096;
            black_box(vaddr);
        });
    });
}

fn bench_translate(c: &mut Criterion) {
    let mut pt = MockPageTable::new(PhysAddr(0x10_0000));
    // Pre-populate with 1000 mappings
    for i in 0..1000u64 {
        pt.map(VirtAddr(0x1000 + i * 4096), PhysAddr(0xA000_0000 + i * 4096),
               PageFlags::READABLE, &mut || None).unwrap();
    }

    c.bench_function("page_table/translate", |b| {
        b.iter(|| {
            let result = pt.translate(VirtAddr(0x1000 + 500 * 4096));
            black_box(result);
        });
    });
}

fn bench_map_unmap_cycle(c: &mut Criterion) {
    c.bench_function("page_table/map_unmap_cycle", |b| {
        let mut pt = MockPageTable::new(PhysAddr(0x10_0000));
        b.iter(|| {
            let vaddr = VirtAddr(0x1000);
            pt.map(vaddr, PhysAddr(0xDEAD_0000), PageFlags::READABLE, &mut || None).unwrap();
            let paddr = pt.unmap(vaddr, &mut |_| {}).unwrap();
            black_box(paddr);
        });
    });
}

criterion_group!(benches, bench_map_single, bench_translate, bench_map_unmap_cycle);
criterion_main!(benches);
```

**Important:** Check if `MockPageTable` and `PageTable` trait are re-exported publicly. They might need `pub use` in `vm/mod.rs`. If not public, the bench file can't import them. Check `crates/harmony-microkernel/src/vm/mod.rs` for public re-exports. If `mock` module is not `pub`, it may need to be made `pub` (or `pub(crate)` won't work from benches).

- [ ] **Step 2: Run and verify**

Run: `cargo bench -p harmony-microkernel --bench page_table`

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-microkernel/benches/page_table.rs
git commit -m "feat(bench): page table map/unmap/translate benchmarks

MockPageTable benchmarks: map_single, translate (1000 entries), map_unmap_cycle.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: FidTracker benchmark

**Files:**
- Create: `crates/harmony-microkernel/benches/fid_tracker.rs`

- [ ] **Step 1: Create fid_tracker.rs**

```rust
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use harmony_microkernel::fid_tracker::FidTracker;

fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("fid_tracker/insert");
    for size in [10, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                let mut tracker = FidTracker::new(0, ());
                for i in 1..=size {
                    tracker.insert(i as u32, i as u64, ()).unwrap();
                }
                black_box(&tracker);
            });
        });
    }
    group.finish();
}

fn bench_get_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("fid_tracker/get");
    for size in [10, 100, 1000] {
        let mut tracker = FidTracker::new(0, ());
        for i in 1..=size {
            tracker.insert(i as u32, i as u64, ()).unwrap();
        }
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                let entry = tracker.get(size as u32 / 2);
                black_box(entry);
            });
        });
    }
    group.finish();
}

fn bench_clunk(c: &mut Criterion) {
    c.bench_function("fid_tracker/clunk", |b| {
        b.iter_batched(
            || {
                let mut tracker = FidTracker::new(0, ());
                for i in 1..=100 {
                    tracker.insert(i, i as u64, ()).unwrap();
                }
                tracker
            },
            |mut tracker| {
                for i in 1..=100 {
                    tracker.clunk(i).unwrap();
                }
                black_box(&tracker);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_insert, bench_get_lookup, bench_clunk);
criterion_main!(benches);
```

**Important:** Check if `FidTracker` is re-exported publicly. It might be at `harmony_microkernel::FidTracker` or `harmony_microkernel::fid_tracker::FidTracker`. Also check if `fid_tracker` module is `pub`.

- [ ] **Step 2: Run and verify**

Run: `cargo bench -p harmony-microkernel --bench fid_tracker`

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-microkernel/benches/fid_tracker.rs
git commit -m "feat(bench): FidTracker insert/get/clunk benchmarks

Parameterized over population sizes (10, 100, 1000 fids).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: IPC echo benchmark

**Files:**
- Create: `crates/harmony-microkernel/benches/ipc_echo.rs`

- [ ] **Step 1: Create ipc_echo.rs**

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use harmony_microkernel::echo::EchoServer;
use harmony_microkernel::{FileServer, OpenMode};

fn bench_walk_open_read_clunk(c: &mut Criterion) {
    c.bench_function("ipc_echo/walk_open_read_clunk", |b| {
        b.iter_batched(
            || EchoServer::new(),
            |mut srv| {
                srv.walk(0, 1, "hello").unwrap();
                srv.open(1, OpenMode::Read).unwrap();
                let data = srv.read(1, 0, 1024).unwrap();
                srv.clunk(1).unwrap();
                black_box(data);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_read_only(c: &mut Criterion) {
    let mut srv = EchoServer::new();
    srv.walk(0, 1, "hello").unwrap();
    srv.open(1, OpenMode::Read).unwrap();

    c.bench_function("ipc_echo/read_only", |b| {
        b.iter(|| {
            let data = srv.read(1, 0, 1024).unwrap();
            black_box(data);
        });
    });
}

criterion_group!(benches, bench_walk_open_read_clunk, bench_read_only);
criterion_main!(benches);
```

**Important:** Check if `EchoServer`, `FileServer`, `OpenMode` are re-exported from the crate root. Adapt import paths.

- [ ] **Step 2: Run and verify**

Run: `cargo bench -p harmony-microkernel --bench ipc_echo`

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-microkernel/benches/ipc_echo.rs
git commit -m "feat(bench): EchoServer IPC round-trip benchmarks

walk→open→read→clunk cycle and repeated read benchmarks.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Cap tracker benchmark

**Files:**
- Create: `crates/harmony-microkernel/benches/cap_tracker.rs`

- [ ] **Step 1: Create cap_tracker.rs**

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use harmony_microkernel::vm::{PhysAddr, FrameClassification, MemoryBudget};
use harmony_microkernel::vm::cap_tracker::CapTracker;

fn bench_check_budget(c: &mut Criterion) {
    let mut tracker = CapTracker::new();
    tracker.set_budget(1, MemoryBudget::new(1024, FrameClassification::all()));

    c.bench_function("cap_tracker/check_budget", |b| {
        b.iter(|| {
            let result = tracker.check_budget(1, 1, FrameClassification::empty());
            black_box(result);
        });
    });
}

fn bench_record_remove_mapping(c: &mut Criterion) {
    c.bench_function("cap_tracker/record_remove_cycle", |b| {
        let mut tracker = CapTracker::new();
        tracker.set_budget(1, MemoryBudget::new(1024, FrameClassification::all()));
        let mut next_addr = 0x1000u64;
        b.iter(|| {
            let addr = PhysAddr(next_addr);
            tracker.record_mapping(addr, 1, FrameClassification::ENCRYPTED);
            tracker.remove_mapping(addr, 1);
            next_addr += 4096;
            black_box(addr);
        });
    });
}

fn bench_frame_classification(c: &mut Criterion) {
    let mut tracker = CapTracker::new();
    tracker.set_budget(1, MemoryBudget::new(1024, FrameClassification::all()));
    // Pre-populate with 100 encrypted frame mappings
    for i in 0..100u64 {
        tracker.record_mapping(PhysAddr(0x1000 + i * 4096), 1, FrameClassification::ENCRYPTED);
    }

    c.bench_function("cap_tracker/frame_classification", |b| {
        b.iter(|| {
            let class = tracker.frame_classification(PhysAddr(0x1000 + 50 * 4096));
            black_box(class);
        });
    });
}

criterion_group!(benches, bench_check_budget, bench_record_remove_mapping, bench_frame_classification);
criterion_main!(benches);
```

**Important:** Check if `CapTracker`, `MemoryBudget`, `FrameClassification` are publicly re-exported. They might need `pub use` or `pub mod` adjustments. Also check `FrameClassification::all()` and `FrameClassification::ENCRYPTED` exist.

- [ ] **Step 2: Run and verify**

Run: `cargo bench -p harmony-microkernel --bench cap_tracker`

- [ ] **Step 3: Commit**

```bash
git add crates/harmony-microkernel/benches/cap_tracker.rs
git commit -m "feat(bench): capability tracker benchmarks

check_budget, record/remove mapping cycle, frame classification lookup.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Full verification

- [ ] **Step 1: Run all benchmarks**

Run: `cargo bench -p harmony-microkernel`
Expected: all 5 bench files produce Criterion output

- [ ] **Step 2: Run workspace tests**

Run: `cargo test --workspace`

- [ ] **Step 3: Run clippy and nightly fmt**

Run: `cargo clippy --workspace && rustup run nightly cargo fmt -- --check`
