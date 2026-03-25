// SPDX-License-Identifier: GPL-2.0-or-later

//! MockRegisterBank benchmarks — read/write baseline for driver operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use harmony_unikernel::drivers::register_bank::mock::MockRegisterBank;
use harmony_unikernel::drivers::register_bank::RegisterBank;

/// Read from a pre-configured offset (sticky value path).
fn bench_read(c: &mut Criterion) {
    let mut bank = MockRegisterBank::new();
    bank.on_read(0x24, vec![0x0001_0000]); // PRESENT_STATE register

    c.bench_function("register_bank/read", |b| {
        b.iter(|| {
            let val = bank.read(black_box(0x24));
            black_box(val);
        });
    });
}

/// Write to a register (appends to writes vec).
fn bench_write(c: &mut Criterion) {
    let mut bank = MockRegisterBank::new();

    c.bench_function("register_bank/write", |b| {
        b.iter(|| {
            bank.write(black_box(0x30), black_box(0xFFFF_FFFF));
        });
    });
}

/// Read-modify-write cycle (typical driver pattern).
fn bench_read_modify_write(c: &mut Criterion) {
    let mut bank = MockRegisterBank::new();
    bank.on_read(0x2C, vec![0x0000_0001]); // CLOCK_CONTROL

    c.bench_function("register_bank/read_modify_write", |b| {
        b.iter(|| {
            let val = bank.read(black_box(0x2C));
            bank.write(black_box(0x2C), black_box(val | 0x0004));
        });
    });
}

criterion_group!(benches, bench_read, bench_write, bench_read_modify_write);
criterion_main!(benches);
