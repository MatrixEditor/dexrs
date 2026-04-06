#![no_main]
#![allow(non_snake_case)]

use dexrs::file::{ClassAccessor, Field};

extern crate dexrs;
extern crate libfuzzer_sys;

fn null_field_visitor(_field: &dexrs::file::Field) -> Result<(), dexrs::error::DexError> {
    Ok(())
}

fn null_method_visitor(_method: &dexrs::file::Method) -> Result<(), dexrs::error::DexError> {
    Ok(())
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    // this must not panic
    if let Ok(ca) = ClassAccessor::from_raw(data) {
        let _fields: Vec<Field> = ca.get_fields().collect();
        if let Ok(methods) = ca.get_methods() {
            let _methods: Vec<_> = methods.collect();
        }

        // visitors shouldn't panic too
        let _res = ca
            .visit_fields_and_methods(
                null_field_visitor,
                null_field_visitor,
                null_method_visitor,
                null_method_visitor,
            )
            .is_ok();
    }
});
