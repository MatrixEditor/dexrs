#![no_main]
#![allow(non_snake_case)]

use dexrs::file::{DexFile, DexLocation};

extern crate dexrs;
extern crate libfuzzer_sys;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // this must not panic
    if let Ok(dex) = DexFile::from_raw_parts(&data, DexLocation::InMemory) {
        // we skip verification to test class_accessor here
        if let Ok(class_def) = dex.get_class_def(0) {
            if let Ok(Some(ca)) = dex.get_class_accessor(&class_def) {
                // must not panic
                let _fields = ca.get_fields();
                let _methods = ca.get_methods();
            }
        }
    }
});
