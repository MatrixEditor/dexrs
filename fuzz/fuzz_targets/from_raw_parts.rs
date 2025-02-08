#![no_main]
#![allow(non_snake_case)]

use dexrs::file::{DexFile, DexLocation};

extern crate dexrs;
extern crate libfuzzer_sys;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // this must not panic
    if let Ok(dex) = DexFile::from_raw_parts(&data, DexLocation::InMemory) {
        if DexFile::verify(&dex, true).is_ok() {
            let _ = dex;
        }
    }
});
