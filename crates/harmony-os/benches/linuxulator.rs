// SPDX-License-Identifier: GPL-2.0-or-later

//! Linuxulator syscall dispatch benchmarks.
//!
//! Measures the overhead of translating Linux syscall numbers + args into
//! Harmony IPC operations. Uses a minimal mock backend that does no real work.

use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use harmony_microkernel::{Fid, FileStat, FileType, IpcError, OpenMode, QPath};
use harmony_os::linuxulator::{Linuxulator, SyscallBackend};

// ── Minimal benchmark backend ───────────────────────────────────────

/// No-op backend for measuring pure syscall dispatch overhead.
struct BenchBackend;

impl SyscallBackend for BenchBackend {
    fn walk(&mut self, _path: &str, _new_fid: Fid) -> Result<QPath, IpcError> {
        Ok(0)
    }

    fn open(&mut self, _fid: Fid, _mode: OpenMode) -> Result<(), IpcError> {
        Ok(())
    }

    fn read(&mut self, _fid: Fid, _offset: u64, count: u32) -> Result<Vec<u8>, IpcError> {
        Ok(vec![0; count as usize])
    }

    fn write(&mut self, _fid: Fid, _offset: u64, data: &[u8]) -> Result<u32, IpcError> {
        Ok(data.len() as u32)
    }

    fn clunk(&mut self, _fid: Fid) -> Result<(), IpcError> {
        Ok(())
    }

    fn stat(&mut self, _fid: Fid) -> Result<FileStat, IpcError> {
        Ok(FileStat {
            qpath: 0,
            name: Arc::from("bench"),
            size: 0,
            file_type: FileType::Regular,
        })
    }
}

// ── Benchmarks ──────────────────────────────────────────────────────

/// Syscall dispatch floor: getpid (x86_64 nr 39).
/// No fd lookup, no buffer, no backend call — pure translation overhead.
fn bench_getpid(c: &mut Criterion) {
    let mut lx = Linuxulator::new(BenchBackend);
    lx.init_stdio().unwrap();

    c.bench_function("linuxulator/getpid", |b| {
        b.iter(|| {
            let result = lx.handle_syscall(black_box(39), black_box([0; 6]));
            black_box(result);
        });
    });
}

/// Realistic hot-path: write to stdout (x86_64 nr 1).
/// Exercises fd lookup + backend dispatch + return.
fn bench_write_stdout(c: &mut Criterion) {
    let mut lx = Linuxulator::new(BenchBackend);
    lx.init_stdio().unwrap();

    // write(fd=1, buf=0x1000, count=64)
    let args = [1u64, 0x1000, 64, 0, 0, 0];

    c.bench_function("linuxulator/write_stdout", |b| {
        b.iter(|| {
            let result = lx.handle_syscall(black_box(1), black_box(args));
            black_box(result);
        });
    });
}

criterion_group!(benches, bench_getpid, bench_write_stdout);
criterion_main!(benches);
