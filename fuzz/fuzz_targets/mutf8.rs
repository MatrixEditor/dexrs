#![no_main]
#![allow(non_snake_case)]

use dexrs::utf;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // end must be a zero
    if let Some(end)  = data.iter().position(|&x| x == 0) {
        if let Ok(s) = utf::mutf8_to_str(&data[0..end]) {
            let _ = s.len();
        }
    }
});
