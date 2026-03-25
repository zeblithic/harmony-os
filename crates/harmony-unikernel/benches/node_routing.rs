// SPDX-License-Identifier: GPL-2.0-or-later

//! Node packet routing benchmarks — measures handle_event throughput.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
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
fn bench_inbound_invalid_packet(c: &mut Criterion) {
    let mut node = Node::new();
    node.register_interface("bench0".into(), InterfaceMode::Full, None);

    // 19 bytes = minimum Header Type1 size, but with invalid flags/dest.
    // The node should parse, find no matching destination, and drop.
    let short_packet = vec![0u8; 19];

    c.bench_function("node_routing/inbound_invalid_packet", |b| {
        b.iter(|| {
            let actions = node.handle_event(black_box(NodeEvent::InboundPacket {
                interface_name: "bench0".into(),
                raw: short_packet.clone(),
                now: 1000,
            }));
            black_box(actions);
        });
    });
}

criterion_group!(benches, bench_timer_tick, bench_inbound_invalid_packet);
criterion_main!(benches);
