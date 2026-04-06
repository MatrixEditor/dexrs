#![no_main]
#![allow(non_snake_case)]

use std::hint::black_box;

use dexrs::file::EncodedCatchHandlerIterator;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(iterator) = EncodedCatchHandlerIterator::new(data) {
        for handler in iterator {
            let _ = black_box(handler);
        }
    }
});
