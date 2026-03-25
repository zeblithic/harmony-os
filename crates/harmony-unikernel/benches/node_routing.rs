// SPDX-License-Identifier: GPL-2.0-or-later

//! Node packet routing benchmarks — measures handle_event throughput.
//!
//! These benchmarks exercise harmony-reticulum's Node directly rather than
//! through UnikernelRuntime, isolating protocol-level packet processing
//! cost from the runtime's peer tracking and heartbeat logic. Placed in
//! harmony-unikernel because Node is a Ring 0 git dependency without its
//! own criterion setup.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use harmony_reticulum::interface::InterfaceMode;
use harmony_reticulum::node::{Node, NodeEvent};

/// TimerTick event — maintenance path (path expiry, announce scheduling).
fn bench_timer_tick(c: &mut Criterion) {
    let mut node = Node::new();
    let mut now_secs = 1u64;

    c.bench_function("node_routing/timer_tick", |b| {
        b.iter(|| {
            let actions = node.handle_event(black_box(NodeEvent::TimerTick { now: now_secs }));
            now_secs += 1;
            black_box(actions);
        });
    });
}

/// InboundPacket event with an invalid/short packet — exercises the
/// parse-and-reject fast path (no routing, no announce processing).
/// Uses iter_batched to isolate parse cost from Vec allocation.
fn bench_inbound_invalid_packet(c: &mut Criterion) {
    let mut node = Node::new();
    node.register_interface("bench0".into(), InterfaceMode::Full, None);

    c.bench_function("node_routing/inbound_invalid_packet", |b| {
        b.iter_batched(
            || vec![0u8; 19], // 19 bytes = min Header Type1, invalid flags/dest
            |raw| {
                let actions = node.handle_event(black_box(NodeEvent::InboundPacket {
                    interface_name: "bench0".into(),
                    raw,
                    now: 1000,
                }));
                black_box(actions);
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_timer_tick, bench_inbound_invalid_packet);
criterion_main!(benches);
