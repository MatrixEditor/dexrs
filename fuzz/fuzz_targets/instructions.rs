// #81835918       REDUCE cov: 439 ft: 2487 corp: 407/57Kb lim: 4096 exec/s: 26796 rss: 631Mb L: 284/3689 MS: 4 ChangeByte-PersAutoDict-ChangeBit-EraseBytes- DE: "\322)\000\000"-
// #81899060       REDUCE cov: 439 ft: 2487 corp: 407/57Kb lim: 4096 exec/s: 26799 rss: 631Mb L: 282/3689 MS: 1 EraseBytes-
// #81909187       REDUCE cov: 439 ft: 2487 corp: 407/57Kb lim: 4096 exec/s: 26802 rss: 631Mb L: 784/3689 MS: 1 EraseBytes-
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