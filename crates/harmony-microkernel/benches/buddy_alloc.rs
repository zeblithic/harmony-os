// SPDX-License-Identifier: GPL-2.0-or-later
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use harmony_microkernel::vm::buddy::BuddyAllocator;
use harmony_microkernel::vm::PhysAddr;

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

criterion_group!(
    benches,
    bench_alloc_frame,
    bench_alloc_free_cycle,
    bench_order_alloc
);
criterion_main!(benches);
