use criterion::{criterion_group, criterion_main, Criterion};
use dexrs::file::{DexFile, DexLocation, InMemoryDexContainer};
use std::hint::black_box;

fn parse_and_verify_small_file(c: &mut Criterion) {
    let data = include_bytes!("../tests/prime/prime.dex");
    c.bench_function("parse_and_verify_small_file", |b| {
        b.iter(|| {
            let buf = black_box(data);
            let container = InMemoryDexContainer::new(buf);
            if let Ok(dex) = DexFile::from_raw_parts(&container, DexLocation::InMemory) {
                if DexFile::verify(&dex, true).is_ok() {
                    black_box(dex);
                }
            }
        })
    });
}

fn parse_small_file(c: &mut Criterion) {
    let data = include_bytes!("../tests/prime/prime.dex");
    c.bench_function("parse_small_file", |b| {
        b.iter(|| {
            let buf = black_box(data);
            let container = InMemoryDexContainer::new(buf);
            if let Ok(dex) = DexFile::from_raw_parts(&container, DexLocation::InMemory) {
                black_box(dex);
            }
        })
    });
}

criterion_group!(benches, parse_and_verify_small_file, parse_small_file);
criterion_main!(benches);
