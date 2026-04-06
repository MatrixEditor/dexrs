use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dexrs::file::{patch::update_checksum, DexEditor, DexFile, DexLocation};

const PRIME: &[u8] = include_bytes!("../tests/prime/prime.dex");

fn bench_editor_from_bytes(c: &mut Criterion) {
    c.bench_function("editor_from_bytes", |b| {
        b.iter(|| black_box(DexEditor::from_bytes(PRIME.to_vec()).unwrap()))
    });
}

fn bench_set_class_flags(c: &mut Criterion) {
    c.bench_function("set_class_flags_and_build", |b| {
        b.iter(|| {
            let mut ed = DexEditor::from_bytes(PRIME.to_vec()).unwrap();
            ed.set_class_access_flags(black_box("Lprime/prime;"), black_box(0x0011u32)).unwrap();
            black_box(ed.build().unwrap());
        })
    });
}

fn bench_rename_same_length(c: &mut Criterion) {
    c.bench_function("rename_class_same_length", |b| {
        b.iter(|| {
            let mut ed = DexEditor::from_bytes(PRIME.to_vec()).unwrap();
            ed.rename_class(black_box("Lprime/prime;"), black_box("Lprime/other;")).unwrap();
            black_box(ed.build().unwrap());
        })
    });
}

fn bench_rename_different_length(c: &mut Criterion) {
    c.bench_function("rename_class_different_length", |b| {
        b.iter(|| {
            let mut ed = DexEditor::from_bytes(PRIME.to_vec()).unwrap();
            ed.rename_class(black_box("Lprime/prime;"), black_box("Lprime/renamed;")).unwrap();
            black_box(ed.build().unwrap());
        })
    });
}

fn bench_update_checksum(c: &mut Criterion) {
    c.bench_function("update_checksum", |b| {
        let mut buf = PRIME.to_vec();
        b.iter(|| update_checksum(black_box(&mut buf)))
    });
}

fn bench_full_pipeline(c: &mut Criterion) {
    c.bench_function("full_edit_pipeline", |b| {
        b.iter(|| {
            let mut ed = DexEditor::from_bytes(PRIME.to_vec()).unwrap();
            ed.set_class_access_flags("Lprime/prime;", 0x0011).unwrap();
            ed.rename_class("Lprime/prime;", "Lprime/renamed;").unwrap();
            let bytes = ed.build().unwrap();
            let dex = DexFile::from_raw_parts(black_box(&bytes), DexLocation::InMemory).unwrap();
            black_box(dex.num_class_defs());
        })
    });
}

criterion_group!(
    benches,
    bench_editor_from_bytes,
    bench_set_class_flags,
    bench_rename_same_length,
    bench_rename_different_length,
    bench_update_checksum,
    bench_full_pipeline,
);
criterion_main!(benches);
