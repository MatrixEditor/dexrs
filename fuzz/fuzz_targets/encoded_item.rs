#![no_main]
#![allow(non_snake_case)]

use dexrs::file::EncodedValue;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    if let Ok(value) = EncodedValue::new(data) {
        match value {
            EncodedValue::Annotation(annotation) => for _ in annotation.elements() {},
            EncodedValue::Array(array) => for _ in array {},
            _ => {}
        }
    }
});
