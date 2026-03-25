// SPDX-License-Identifier: GPL-2.0-or-later

//! Event loop benchmarks — measures UnikernelRuntime::tick() throughput.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use harmony_identity::PrivateIdentity;
use harmony_unikernel::platform::entropy::KernelEntropy;
use harmony_unikernel::{MemoryState, UnikernelRuntime};

fn make_entropy() -> KernelEntropy<impl FnMut(&mut [u8])> {
    let mut counter: u8 = 42;
    KernelEntropy::new(move |buf: &mut [u8]| {
        for byte in buf.iter_mut() {
            *byte = counter;
            counter = counter.wrapping_add(7);
        }
    })
}

/// Idle tick: no peers, no pending announces, no inbound packets.
/// Measures the floor of the event loop overhead.
fn bench_tick_idle(c: &mut Criterion) {
    let mut entropy = make_entropy();
    let identity = PrivateIdentity::generate(&mut entropy);
    let persistence = MemoryState::new();
    let mut rt = UnikernelRuntime::new(identity, entropy, persistence);

    let mut now_ms = 1000u64;

    c.bench_function("event_loop/tick_idle", |b| {
        b.iter(|| {
            let actions = rt.tick(black_box(now_ms));
            now_ms += 10; // advance 10ms per tick
            black_box(actions);
        });
    });
}

/// Tick with a registered announcing destination — exercises the
/// announce-needed check path.
fn bench_tick_with_announce(c: &mut Criterion) {
    let mut entropy = make_entropy();
    let identity = PrivateIdentity::generate(&mut entropy);
    let persistence = MemoryState::new();
    let mut rt = UnikernelRuntime::new(identity, entropy, persistence);

    // Register a destination so the node has announce work to consider.
    rt.register_announcing_destination("harmony", &["bench"], 300_000, 0);

    let mut now_ms = 1000u64;

    c.bench_function("event_loop/tick_with_announce", |b| {
        b.iter(|| {
            let actions = rt.tick(black_box(now_ms));
            now_ms += 10;
            black_box(actions);
        });
    });
}

criterion_group!(benches, bench_tick_idle, bench_tick_with_announce);
criterion_main!(benches);
