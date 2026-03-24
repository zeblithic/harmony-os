// SPDX-License-Identifier: GPL-2.0-or-later
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use harmony_microkernel::vm::mock::MockPageTable;
use harmony_microkernel::vm::page_table::PageTable;
use harmony_microkernel::vm::{PageFlags, PhysAddr, VirtAddr};

fn bench_map_single(c: &mut Criterion) {
    c.bench_function("page_table/map_single", |b| {
        b.iter_batched(
            || MockPageTable::new(PhysAddr(0x10_0000)),
            |mut pt| {
                pt.map(
                    VirtAddr(0x1000),
                    PhysAddr(0xDEAD_0000),
                    PageFlags::READABLE | PageFlags::WRITABLE,
                    &mut || None,
                )
                .unwrap();
                black_box(pt)
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_translate(c: &mut Criterion) {
    let mut pt = MockPageTable::new(PhysAddr(0x10_0000));
    // Pre-populate with 1000 mappings
    for i in 0..1000u64 {
        pt.map(
            VirtAddr(0x1000 + i * 4096),
            PhysAddr(0xA000_0000 + i * 4096),
            PageFlags::READABLE,
            &mut || None,
        )
        .unwrap();
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
            pt.map(
                vaddr,
                PhysAddr(0xDEAD_0000),
                PageFlags::READABLE,
                &mut || None,
            )
            .unwrap();
            let paddr = pt.unmap(vaddr, &mut |_| {}).unwrap();
            black_box(paddr);
        });
    });
}

criterion_group!(
    benches,
    bench_map_single,
    bench_translate,
    bench_map_unmap_cycle
);
criterion_main!(benches);
