use criterion::{criterion_group, criterion_main, Criterion, black_box};
use dexrs::file::{verifier::VerifyPreset, DexFile, DexLocation, Header, InMemoryDexContainer};

fn parse_and_verify_small_file(c: &mut Criterion) {
    let data = include_bytes!("../tests/prime/prime.dex");
    c.bench_function("parse_and_verify_small_file", |b| {
        b.iter(|| {
            let container = InMemoryDexContainer::new(data);
            if let Ok(dex) = DexFile::from_raw_parts(&container, DexLocation::InMemory) {
                if DexFile::verify(&dex, VerifyPreset::All).is_ok() {
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

// REVISIT: this is not a real benchmark
macro_rules! parse_strings {
    ($name:ident, $lossy:ident) => {
        fn $name(c: &mut Criterion) {
            let data = include_bytes!("../tests/prime/prime.dex");
            c.bench_function("parse_strings", |b| {
                b.iter(|| {
                    let container = InMemoryDexContainer::new(data);
                    if let Ok(dex) = DexFile::from_raw_parts(&container, DexLocation::InMemory) {
                        for string_id in dex.get_string_ids() {
                            if let Ok(_) = dex.$lossy(string_id) {
                                black_box(string_id);
                            }
                        }
                    }
                })
            });
        }
    };
}

parse_strings!(parse_strings_lossy, get_utf16_str_lossy);
parse_strings!(parse_strings, get_utf16_str);

criterion_group!(benches, parse_and_verify_small_file, parse_small_file, parse_strings_lossy, parse_strings);
criterion_main!(benches);
