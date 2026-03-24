# Criterion Benchmarks for Ring 2 Microkernel Operations

**Bead:** harmony-os-hb2
**Date:** 2026-03-23
**Status:** Draft

## Problem

No benchmarks exist in harmony-os. There are no baseline performance numbers
for core kernel operations, making it impossible to detect regressions or
validate RPi5 hardware performance against QEMU results.

## Solution

Add Criterion benchmarks for the five highest-impact Ring 2 (microkernel)
components: buddy allocator, page table, FidTracker, 9P IPC (EchoServer),
and capability tracker. Establishes the benchmark framework (`benches/`
directory, Criterion setup) for future Ring 1 and Ring 3 benchmarks.

## Design Decisions

### Criterion 0.5 with html_reports

Criterion is the standard Rust benchmarking framework. Version 0.5 with
`html_reports` generates comparison reports across runs. Uses `harness = false`
bench targets for full control over setup/teardown.

### One bench file per component

Each component gets its own bench file for independent execution and clear
CI reporting. Bench files mirror the test setup patterns from existing unit
tests — same constructors, same mock types.

### MockPageTable for page table benchmarks

Real page tables (Aarch64PageTable, X86_64PageTable) require platform-specific
setup (heap arenas, identity phys_to_virt). MockPageTable uses BTreeMap
internally and runs on any host — the goal is measuring operation overhead,
not hardware page table walk latency.

## Architecture

### Benchmark Files

| File | Component | Key benchmarks |
|------|-----------|---------------|
| `benches/buddy_alloc.rs` | BuddyAllocator | alloc_frame, free_frame, order-N alloc, coalescing |
| `benches/page_table.rs` | MockPageTable | map, unmap, translate, map+unmap cycle |
| `benches/fid_tracker.rs` | FidTracker | insert, get, clunk at 10/100/1000 population |
| `benches/ipc_echo.rs` | EchoServer | walk→open→read→clunk round-trip |
| `benches/cap_tracker.rs` | CapTracker | check_budget, record_mapping, remove_mapping |

### Setup Changes

Workspace `Cargo.toml`:
```toml
[workspace.dependencies]
criterion = { version = "0.5", features = ["html_reports"] }
```

`crates/harmony-microkernel/Cargo.toml`:
```toml
[dev-dependencies]
criterion = { workspace = true }

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

### Benchmark Details

**buddy_alloc.rs:**
- `alloc_frame` — single frame from a 1024-frame allocator
- `free_frame` — free then re-alloc (measures free + coalesce)
- `alloc_free_cycle` — alloc + free in tight loop
- `order_n_alloc` — parameterized over orders 0-5

**page_table.rs:**
- `map_single` — map one page
- `translate` — lookup an existing mapping
- `map_unmap_cycle` — map + unmap in tight loop
- `map_100_pages` — sequential region mapping

**fid_tracker.rs:**
- `insert` — add a new fid
- `get_lookup` — lookup existing fid
- `clunk` — remove a fid
- Parameterized over population sizes (10, 100, 1000)

**ipc_echo.rs:**
- `walk_open_read_clunk` — full 9P round-trip on EchoServer
- `read_only` — repeated reads on an open fid
- `walk_depth` — walk to nested file

**cap_tracker.rs:**
- `check_budget` — fast-path budget check
- `record_mapping` — insert encrypted frame mapping
- `remove_mapping` — remove frame mapping
- `frame_classification` — read-only lookup

## File Changes

| File | Change |
|------|--------|
| `Cargo.toml` (workspace) | Add criterion to workspace dependencies |
| `crates/harmony-microkernel/Cargo.toml` | Add criterion dev-dep + 5 bench targets |
| `crates/harmony-microkernel/benches/buddy_alloc.rs` | New: buddy allocator benchmarks |
| `crates/harmony-microkernel/benches/page_table.rs` | New: page table benchmarks |
| `crates/harmony-microkernel/benches/fid_tracker.rs` | New: FidTracker benchmarks |
| `crates/harmony-microkernel/benches/ipc_echo.rs` | New: EchoServer IPC benchmarks |
| `crates/harmony-microkernel/benches/cap_tracker.rs` | New: capability tracker benchmarks |

## What is NOT in Scope

- No Ring 1 benchmarks (event loop, drivers) — harmony-os-cq4
- No Ring 3 benchmarks (Linuxulator, ELF, NAR) — harmony-os-gsv
- No QEMU or real-hardware benchmarks (harmony-os-4gb)
- No CI integration for benchmark regression tracking (future work)

## Testing

- `cargo bench -p harmony-microkernel` runs all benchmarks
- Each benchmark produces Criterion HTML reports in `target/criterion/`
- Verify all 5 bench files compile and produce output
- Existing unit tests unaffected
