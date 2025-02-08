use criterion::{criterion_group, criterion_main, Criterion};
use dexrs::file::{DexFile, DexLocation, Header, InMemoryDexContainer};

fn parse_and_verify_small_file(c: &mut Criterion) {
    let data = include_bytes!("../tests/prime/prime.dex");
    c.bench_function("parse_and_verify_small_file", |b| {
        b.iter(|| {
            let container = InMemoryDexContainer::new(data);
            if let Ok(dex) = DexFile::from_raw_parts(&container, DexLocation::InMemory) {
                if DexFile::verify(&dex, true).is_ok() {
                    assert_eq!(
                        dex.expected_header_size(),
                        std::mem::size_of::<Header>() as u32
                    );
                }
            }
        })
    });
}

fn parse_small_file(c: &mut Criterion) {
    let data = include_bytes!("../tests/prime/prime.dex");
    c.bench_function("parse_small_file", |b| {
        b.iter(|| {
            let container = InMemoryDexContainer::new(data);
            if let Ok(dex) = DexFile::from_raw_parts(&container, DexLocation::InMemory) {
                assert_eq!(
                    dex.expected_header_size(),
                    std::mem::size_of::<Header>() as u32
                );
            }
        })
    });
}

criterion_group!(benches, parse_and_verify_small_file, parse_small_file);
criterion_main!(benches);
