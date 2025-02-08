#![no_main]
#![allow(non_snake_case)]

use dexrs::file::{DexFile, DexLocation, InMemoryDexContainer};

extern crate libfuzzer_sys;
extern crate dexrs;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // this must not panic
    if let Ok(dex) = DexFile::from_raw_parts(&data, DexLocation::InMemory) {
        let _ = dex;
    }
});
