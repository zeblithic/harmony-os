// SPDX-License-Identifier: GPL-2.0-or-later
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
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
            BatchSize::SmallInput,
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
