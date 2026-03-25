// SPDX-License-Identifier: GPL-2.0-or-later

//! NAR archive parsing benchmarks.
//!
//! Measures the cost of parsing NAR archives of varying complexity:
//! a single-file NAR and a directory with multiple entries.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use harmony_microkernel::nar::NarArchive;

// ── NAR construction helpers ────────────────────────────────────────

/// Encode a byte slice as a NAR string: 8-byte LE length + data + zero-padding.
fn nar_string(s: &[u8]) -> Vec<u8> {
    let len = s.len() as u64;
    let padded_len = (s.len() + 7) & !7;
    let mut buf = Vec::with_capacity(8 + padded_len);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(s);
    buf.resize(buf.len() + (padded_len - s.len()), 0);
    buf
}

/// Build a NAR containing a single regular file.
fn build_single_file_nar(contents: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&nar_string(b"nix-archive-1"));
    buf.extend_from_slice(&nar_string(b"("));
    buf.extend_from_slice(&nar_string(b"type"));
    buf.extend_from_slice(&nar_string(b"regular"));
    buf.extend_from_slice(&nar_string(b"contents"));
    buf.extend_from_slice(&nar_string(contents));
    buf.extend_from_slice(&nar_string(b")"));
    buf
}

/// Build a NAR containing a directory with `n` regular file entries.
fn build_directory_nar(n: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&nar_string(b"nix-archive-1"));
    buf.extend_from_slice(&nar_string(b"("));
    buf.extend_from_slice(&nar_string(b"type"));
    buf.extend_from_slice(&nar_string(b"directory"));
    for i in 0..n {
        // NAR directory entries must be in sorted order.
        let name = format!("file-{i:04}");
        let content = format!("content of {name}");
        buf.extend_from_slice(&nar_string(b"entry"));
        buf.extend_from_slice(&nar_string(b"("));
        buf.extend_from_slice(&nar_string(b"name"));
        buf.extend_from_slice(&nar_string(name.as_bytes()));
        buf.extend_from_slice(&nar_string(b"node"));
        buf.extend_from_slice(&nar_string(b"("));
        buf.extend_from_slice(&nar_string(b"type"));
        buf.extend_from_slice(&nar_string(b"regular"));
        buf.extend_from_slice(&nar_string(b"contents"));
        buf.extend_from_slice(&nar_string(content.as_bytes()));
        buf.extend_from_slice(&nar_string(b")"));
        buf.extend_from_slice(&nar_string(b")"));
    }
    buf.extend_from_slice(&nar_string(b")"));
    buf
}

// ── Benchmarks ──────────────────────────────────────────────────────

fn bench_parse_single_file(c: &mut Criterion) {
    let nar = build_single_file_nar(b"hello world benchmark data for NAR parsing");

    c.bench_function("nar_parse/single_file", |b| {
        b.iter(|| {
            let archive = NarArchive::parse(black_box(&nar)).unwrap();
            black_box(archive);
        });
    });
}

fn bench_parse_directory_10(c: &mut Criterion) {
    let nar = build_directory_nar(10);

    c.bench_function("nar_parse/directory_10_entries", |b| {
        b.iter(|| {
            let archive = NarArchive::parse(black_box(&nar)).unwrap();
            black_box(archive);
        });
    });
}

fn bench_parse_directory_100(c: &mut Criterion) {
    let nar = build_directory_nar(100);

    c.bench_function("nar_parse/directory_100_entries", |b| {
        b.iter(|| {
            let archive = NarArchive::parse(black_box(&nar)).unwrap();
            black_box(archive);
        });
    });
}

criterion_group!(
    benches,
    bench_parse_single_file,
    bench_parse_directory_10,
    bench_parse_directory_100
);
criterion_main!(benches);
