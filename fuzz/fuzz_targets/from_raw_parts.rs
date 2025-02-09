#![no_main]
#![allow(non_snake_case)]

use dexrs::file::{verifier::VerifyPreset, DexFile, DexLocation};

extern crate dexrs;
extern crate libfuzzer_sys;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // this must not panic
    if let Ok(dex) = DexFile::from_raw_parts(&data, DexLocation::InMemory) {
        if DexFile::verify(&dex, VerifyPreset::All).is_ok() {
            if let Ok(_) = dex.get_class_def(0) {}
        }
    }
});
