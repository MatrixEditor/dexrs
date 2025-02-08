#![no_main]
#![allow(non_snake_case)]

use dexrs::file::DexInstructionIterator;

extern crate dexrs;
extern crate libfuzzer_sys;
extern crate plain;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(bytes) = plain::slice_from_bytes::<u16>(data) {
        // Two aspects
        let iter = DexInstructionIterator::new(bytes);
        for inst in iter {
            if let Ok(inst_dump) = inst.to_string(None) {
                assert!(inst_dump.len() > 0);
            }
        }
    }
});