// SPDX-License-Identifier: GPL-2.0-or-later
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use harmony_microkernel::fid_tracker::FidTracker;

fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("fid_tracker/insert");
    for size in [10, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                let mut tracker: FidTracker<()> = FidTracker::new(0, ());
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
        let mut tracker: FidTracker<()> = FidTracker::new(0, ());
        for i in 1..=size {
            tracker.insert(i as u32, i as u64, ()).unwrap();
        }
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                let entry = tracker.get(size as u32 / 2).ok();
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
                let mut tracker: FidTracker<()> = FidTracker::new(0, ());
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
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_insert, bench_get_lookup, bench_clunk);
criterion_main!(benches);
