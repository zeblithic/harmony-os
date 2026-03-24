// SPDX-License-Identifier: GPL-2.0-or-later
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use harmony_microkernel::vm::cap_tracker::{CapTracker, MemoryBudget};
use harmony_microkernel::vm::{FrameClassification, PhysAddr};

fn bench_check_budget(c: &mut Criterion) {
    let mut tracker = CapTracker::new();
    tracker.set_budget(1, MemoryBudget::new(1024, FrameClassification::all()));

    // Sanity check: verify setup is correct before benchmarking.
    tracker
        .check_budget(1, 1, FrameClassification::empty())
        .expect("setup: check_budget should succeed with empty classification");

    c.bench_function("cap_tracker/check_budget", |b| {
        b.iter(|| {
            let result = tracker
                .check_budget(1, 1, FrameClassification::empty())
                .ok();
            black_box(result);
        });
    });
}

fn bench_record_remove_mapping(c: &mut Criterion) {
    c.bench_function("cap_tracker/record_remove_cycle", |b| {
        let mut tracker = CapTracker::new();
        tracker.set_budget(
            1,
            MemoryBudget::new(1024 * 4096, FrameClassification::all()),
        );
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
    tracker.set_budget(
        1,
        MemoryBudget::new(1024 * 4096, FrameClassification::all()),
    );
    // Pre-populate with 100 encrypted frame mappings
    for i in 0..100u64 {
        tracker.record_mapping(
            PhysAddr(0x1000 + i * 4096),
            1,
            FrameClassification::ENCRYPTED,
        );
    }

    c.bench_function("cap_tracker/frame_classification", |b| {
        b.iter(|| {
            let class = tracker.frame_classification(PhysAddr(0x1000 + 50 * 4096));
            black_box(class);
        });
    });
}

criterion_group!(
    benches,
    bench_check_budget,
    bench_record_remove_mapping,
    bench_frame_classification
);
criterion_main!(benches);
